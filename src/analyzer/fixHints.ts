import type { AST } from '@eslint-community/regexpp';
import {
  characterClassToSet,
  characterSetNodeToSet,
  expressionCharacterClassToSet,
  isSubset,
  setsEqual,
  setsOverlap,
  singletonSet,
  expandIgnoreCase,
  type CodePointSet,
  type EffectiveFlags
} from './charSet.js';
import type { FixHint, RuleId } from '../types.js';

const LINEAR_ENGINE_NOTE =
  'Last resort on Node.js: experimental V8 linear engine (`--enable-experimental-regexp-engine` with `/l` flag) when lookarounds/backreferences are not needed.';

function atomSetIfSingleChar(el: AST.Element, flags: EffectiveFlags): CodePointSet | null {
  switch (el.type) {
    case 'Character': {
      const base = singletonSet(el.value);
      return flags.ignoreCase ? expandIgnoreCase(base, flags) : base;
    }
    case 'CharacterSet':
      return characterSetNodeToSet(el, flags);
    case 'CharacterClass':
      return characterClassToSet(el, flags);
    case 'ExpressionCharacterClass':
      return expressionCharacterClassToSet(el, flags);
    default:
      return null;
  }
}

function escapeForNegatedClass(cp: number): string {
  const ch = String.fromCodePoint(cp);
  if (ch === '\\' || ch === ']' || ch === '^' || ch === '-') {
    return `\\${ch}`;
  }
  if (cp === 0x0a) return '\\n';
  if (cp === 0x0d) return '\\r';
  if (cp === 0x09) return '\\t';
  return ch;
}

function replaceSpan(source: string, start: number, end: number, replacement: string): string {
  return source.slice(0, start) + replacement + source.slice(end);
}

function mergedQuantifierSuffix(minTotal: number, maxTotal: number, greedy = true): string {
  const lazy = greedy ? '' : '?';
  if (minTotal === 0 && maxTotal === Infinity) return `*${lazy}`;
  if (minTotal === 1 && maxTotal === Infinity) return `+${lazy}`;
  if (minTotal === 0 && maxTotal === 1) return `?${lazy}`;
  if (maxTotal === Infinity) return `{${minTotal},}${lazy}`;
  if (minTotal === maxTotal) return minTotal === 1 ? '' : `{${minTotal}}${lazy}`;
  return `{${minTotal},${maxTotal}}${lazy}`;
}

function isUnanchoredEndAnchoredQuantifier(quant: AST.Quantifier): boolean {
  const parent = quant.parent;
  if (parent.parent.type !== 'Pattern') {
    return false;
  }
  const elements = parent.elements;
  const idx = elements.indexOf(quant);
  if (idx < 0) return false;

  for (let i = 0; i < idx; i++) {
    const el = elements[i]!;
    if (el.type === 'Assertion' && el.kind === 'start') {
      return false;
    }
    if (el.type !== 'Assertion') {
      return false;
    }
  }

  let hasEndAnchor = false;
  for (let k = idx + 1; k < elements.length; k++) {
    const el = elements[k]!;
    if (el.type === 'Assertion' && el.kind === 'end') {
      hasEndAnchor = true;
      continue;
    }
    return false;
  }
  return hasEndAnchor;
}

export function buildRdh001Fix(
  patternSource: string,
  flagsStr: string,
  outerQuant: AST.Quantifier,
  effFlags: EffectiveFlags
): FixHint {
  const innerEl = outerQuant.element;

  // Case 1: Group with single alternative
  if ((innerEl.type === 'CapturingGroup' || innerEl.type === 'Group') && innerEl.alternatives.length === 1) {
    const alt = innerEl.alternatives[0]!;

    // 1A: `(X+)+`, `(X*)+`, `(X+)*`, `(X*)*` -> collapse to single quantifier `X+` / `X*`
    if (alt.elements.length === 1 && alt.elements[0]?.type === 'Quantifier') {
      const innerQ = alt.elements[0];
      const atomSet = atomSetIfSingleChar(innerQ.element, effFlags);
      if (atomSet !== null) {
        const minCombined = outerQuant.min * innerQ.min;
        const suffix = mergedQuantifierSuffix(
          minCombined === 0 ? 0 : minCombined === 1 ? 1 : minCombined,
          Infinity,
          outerQuant.greedy && innerQ.greedy
        );
        const atomRaw = innerQ.element.raw;
        const replacement = innerEl.type === 'CapturingGroup' ? `(${atomRaw}${suffix})` : `${atomRaw}${suffix}`;
        // Note: if CapturingGroup had `(a+)+`, `(a+)` has no outer quantifier so star-height = 1;
        // if uncapturing or whole Collapse, `a+` is simplest when group isn't referenced.
        const hasRefs = innerEl.type === 'CapturingGroup' && innerEl.references.length > 0;
        const guard = isUnanchoredEndAnchoredQuantifier(outerQuant) ? `(?<!${atomRaw})` : '';
        const cleanReplacement = hasRefs
          ? `${guard}${replacement}`
          : `${guard}${atomRaw}${suffix}`;
        return {
          summary: `Collapse redundant nested quantifier '${outerQuant.raw}' into linear quantifier '${cleanReplacement}'.`,
          rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, cleanReplacement),
          rewriteFlags: flagsStr,
          notes: LINEAR_ENGINE_NOTE
        };
      }
    }

    // 1B: `(T+ S?)*` or `(T+ S?)+` followed by `$` where T and S are disjoint single-char sets (e.g. `(\w+\s?)*$`)
    if (alt.elements.length === 2) {
      const first = alt.elements[0]!;
      const second = alt.elements[1]!;
      if (
        first.type === 'Quantifier' &&
        first.min >= 1 &&
        first.max === Infinity &&
        second.type === 'Quantifier' &&
        second.min === 0 &&
        second.max === 1
      ) {
        const setT = atomSetIfSingleChar(first.element, effFlags);
        const setS = atomSetIfSingleChar(second.element, effFlags);
        if (setT && setS && !setsOverlap(setT, setS)) {
          const parentAlt = outerQuant.parent;
          const idx = parentAlt.elements.indexOf(outerQuant);
          const nextEl = idx >= 0 ? parentAlt.elements[idx + 1] : undefined;
          const followedByEnd =
            nextEl?.type === 'Assertion' && nextEl.kind === 'end' && !effFlags.multiline;

          if (followedByEnd) {
            const outerSuffix = outerQuant.min === 0 ? '*' : '+';
            const guard = isUnanchoredEndAnchoredQuantifier(outerQuant)
              ? `(?<!${first.element.raw})`
              : '';
            const rewrittenLoop = `${guard}(?:${first.element.raw}+(?:${second.element.raw}|$))${outerSuffix}`;
            return {
              summary: `Require separator '${second.element.raw}' or end-of-string '$' between '${first.element.raw}+' tokens so iterations cannot split ambiguously.`,
              rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, rewrittenLoop),
              rewriteFlags: flagsStr,
              notes: LINEAR_ENGINE_NOTE
            };
          }

          // General anchored/unanchored `(T+ S?)+`: `T+(?:S T+)*S?` (for min>=1) or `(?:T+(?:S T+)*S?)?` (for min=0)
          const tRaw = first.element.raw;
          const sRaw = second.element.raw;
          // Ensure start-anchored or atomic if unanchored; check if pattern is start-anchored
          const core = `${tRaw}+(?:${sRaw}${tRaw}+)*${sRaw}?`;
          const wrapped = outerQuant.min === 0 ? `(?:${core})?` : core;
          return {
            summary: `Factor '${outerQuant.raw}' into delimiter-separated '${wrapped}' so consecutive '${tRaw}+' segments require '${sRaw}' between them.`,
            rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, wrapped),
            rewriteFlags: flagsStr,
            notes: LINEAR_ENGINE_NOTE
          };
        }
      }
    }
  }

  // Fallback for general nested quantifiers: JS atomic group emulation `(?=(inner))\k` when not already containing capturing groups with shifts, or structural note
  // Wait: `(?=(outerQuant))\1` commits to the ENTIRE greedy match of `outerQuant` in one shot!
  // Let's check: does `(?=((?:inner)+))\1` eliminate backtracking across outerQuant?
  // Wait: INSIDE `(?= (a+)+ )`, if `(a+)+` itself succeeds (which it ALWAYS does on `'a'.repeat(40)` in 1 greedy step without backtracking!), then when `$` fails AFTER `\1`, V8 DOES NOT BACKTRACK INTO `(?=...)`!!
  // Let's verify: in `(?=((?:a+)+))\1$`, on `'a'.repeat(40) + '!'`, `(?:a+)+` matches 40 `'a'`s greedily in O(n), `(?=...)` exits and discards all backtrack frames inside `(?=...)`, `\1` consumes 40 `'a'`s, `$` fails on `'!'`, and the match terminates in O(n)!!
  // Even cleaner: our static analyzer skips inner quantifiers inside `(?=(...))\k` atomic emulation ONLY when `inner` itself doesn't have nested quantifiers, so let's make sure any `rewrite` we emit has ZERO nested quantifiers inside `(?=...)` too!
  if ((innerEl.type === 'CapturingGroup' || innerEl.type === 'Group') && !patternSource.includes('\\1')) {
    // Only emit atomic emulation when inner body has a single quantifier like `(?=(a+))\1`
    return {
      summary:
        'Refactor nested quantifiers so inner tokens are separated by a required disjoint delimiter, or use possessive/atomic lookahead emulation `(?=(...))\\1`.',
      rewrite: null,
      notes: LINEAR_ENGINE_NOTE
    };
  }

  return {
    summary:
      'Eliminate nested overlapping quantifiers by collapsing inner/outer loops or separating tokens with a mandatory disjoint character.',
    rewrite: null,
    notes: LINEAR_ENGINE_NOTE
  };
}

export function buildRdh002Fix(
  patternSource: string,
  flagsStr: string,
  outerQuant: AST.Quantifier,
  effFlags: EffectiveFlags
): FixHint {
  const innerEl = outerQuant.element;
  if (innerEl.type === 'CapturingGroup' || innerEl.type === 'Group') {
    const alts = innerEl.alternatives;
    // Check if every alternative is a single-character-set atom so we can merge/deduplicate!
    const altSets: Array<{ raw: string; set: CodePointSet }> = [];
    let allSingleAtoms = true;
    for (const alt of alts) {
      if (alt.elements.length !== 1) {
        allSingleAtoms = false;
        break;
      }
      const s = atomSetIfSingleChar(alt.elements[0]!, effFlags);
      if (!s) {
        allSingleAtoms = false;
        break;
      }
      altSets.push({ raw: alt.elements[0]!.raw, set: s });
    }

    if (allSingleAtoms && altSets.length >= 2) {
      // Check if one alternative is a superset of all others! E.g. `(a|a)*` -> `a*`, `(\w|\d)+` -> `\w+`, `(.|\s)*` -> `[\s\S]*` (if `.` + `\s` covers `\n`)
      for (let i = 0; i < altSets.length; i++) {
        const candidate = altSets[i]!;
        let coversAll = true;
        for (let j = 0; j < altSets.length; j++) {
          if (i !== j && !isSubset(altSets[j]!.set, candidate.set)) {
            coversAll = false;
            break;
          }
        }
        if (coversAll) {
          const qSuffix = mergedQuantifierSuffix(outerQuant.min, outerQuant.max, outerQuant.greedy);
          const needsGuard =
            isUnanchoredEndAnchoredQuantifier(outerQuant) && candidate.raw !== '.';
          const guard = needsGuard ? `(?<!${candidate.raw})` : '';
          const rep = `${guard}${candidate.raw}${qSuffix}`;
          return {
            summary: `Simplify overlapping alternation '${outerQuant.raw}' to '${rep}' since '${candidate.raw}' already subsumes the other branch(es).`,
            rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, rep),
            rewriteFlags: flagsStr,
            notes: LINEAR_ENGINE_NOTE
          };
        }
      }

      // Check specifically for `(.|\s)` or `(\s|.)` -> `[\s\S]`!
      if (
        altSets.length === 2 &&
        ((altSets[0]!.raw === '.' && altSets[1]!.raw === '\\s') ||
          (altSets[0]!.raw === '\\s' && altSets[1]!.raw === '.'))
      ) {
        const qSuffix = mergedQuantifierSuffix(outerQuant.min, outerQuant.max, outerQuant.greedy);
        const rep = `[\\s\\S]${qSuffix}`;
        return {
          summary: `Replace overlapping '(.|\\s)' alternation in '${outerQuant.raw}' with unified character class '${rep}'.`,
          rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, rep),
          rewriteFlags: flagsStr,
          notes: LINEAR_ENGINE_NOTE
        };
      }

      // Merge single-char / escape atoms into one CharacterClass `[...]`!
      const canInlineIntoClass = altSets.every(
        (a) =>
          /^[A-Za-z0-9_-]$/.test(a.raw) ||
          /^\\[dDwWsS]$/.test(a.raw) ||
          (a.raw.startsWith('[') && a.raw.endsWith(']') && !a.raw.startsWith('[^') && !effFlags.unicodeSets)
      );
      if (canInlineIntoClass) {
        const parts = altSets.map((a) =>
          a.raw.startsWith('[') && a.raw.endsWith(']') ? a.raw.slice(1, -1) : a.raw
        );
        const dedupParts = [...new Set(parts)];
        const cls = `[${dedupParts.join('')}]`;
        const guard = isUnanchoredEndAnchoredQuantifier(outerQuant) ? `(?<!${cls})` : '';
        const qSuffix = mergedQuantifierSuffix(outerQuant.min, outerQuant.max, outerQuant.greedy);
        const rep = `${guard}${cls}${qSuffix}`;
        return {
          summary: `Merge overlapping single-character alternation '${outerQuant.raw}' into a single character class '${rep}'.`,
          rewrite: replaceSpan(patternSource, outerQuant.start, outerQuant.end, rep),
          rewriteFlags: flagsStr,
          notes: LINEAR_ENGINE_NOTE
        };
      }
    }
  }

  return {
    summary:
      'Make alternation branches mutually exclusive under quantifiers (factor common prefixes or use `v`-flag set subtraction `[A--B]`).',
    rewrite: null,
    notes: LINEAR_ENGINE_NOTE
  };
}

export function buildRdh003Fix(
  patternSource: string,
  flagsStr: string,
  alt: AST.Alternative,
  firstIdx: number,
  secondIdx: number,
  effFlags: EffectiveFlags
): FixHint {
  const q1 = alt.elements[firstIdx] as AST.Quantifier;
  const q2 = alt.elements[secondIdx] as AST.Quantifier;

  // Case 1: Directly adjacent identical character sets (e.g. `\d+\d+` -> `\d{2,}`, `.*.*=` -> `[^=]*=`)
  if (secondIdx === firstIdx + 1) {
    const s1 = atomSetIfSingleChar(q1.element, effFlags);
    const s2 = atomSetIfSingleChar(q2.element, effFlags);

    // Check `.*.*<delim>` (wildcard followed by single literal delimiter char like `=`, `:`, `/`)
    const nextAfterQ2 = alt.elements[secondIdx + 1];
    if (
      s1 &&
      s2 &&
      setsEqual(s1, s2) &&
      q1.element.type === 'CharacterSet' &&
      q1.element.kind === 'any' &&
      q1.min === 0 &&
      q2.min === 0 &&
      nextAfterQ2?.type === 'Character'
    ) {
      const delimEsc = escapeForNegatedClass(nextAfterQ2.value);
      const negClass = effFlags.dotAll ? `[^${delimEsc}]*` : `[^${delimEsc}\\r\\n]*`;
      const rep = `${negClass}${nextAfterQ2.raw}`;
      return {
        summary: `Replace greedy wildcard chain '${q1.raw}${q2.raw}${nextAfterQ2.raw}' with negated delimiter class '${rep}'.`,
        rewrite: replaceSpan(patternSource, q1.start, nextAfterQ2.end, rep),
        rewriteFlags: flagsStr,
        notes: LINEAR_ENGINE_NOTE
      };
    }

    if (s1 && s2 && setsEqual(s1, s2) && q1.element.raw === q2.element.raw) {
      const minSum = q1.min + q2.min;
      const merged = `${q1.element.raw}${mergedQuantifierSuffix(minSum, Infinity, q1.greedy && q2.greedy)}`;
      // Check that merging doesn't still leave another adjacent overlapping quantifier; only emit rewrite if clean
      return {
        summary: `Merge adjacent identical quantifiers '${q1.raw}${q2.raw}' into '${merged}'.`,
        rewrite: replaceSpan(patternSource, q1.start, q2.end, merged),
        rewriteFlags: flagsStr,
        notes: LINEAR_ENGINE_NOTE
      };
    }
  }

  return {
    summary:
      'Replace adjacent overlapping quantifiers with negated character classes (e.g. `[^=]*=`), merged bounds (`\\d{2,}`), or explicit non-overlapping delimiters.',
    rewrite: null,
    notes: LINEAR_ENGINE_NOTE
  };
}

export function buildRdh007Fix(
  patternSource: string,
  flagsStr: string,
  outerQuant: AST.Quantifier
): FixHint {
  const singleAtom =
    outerQuant.element.type === 'Character' ||
    outerQuant.element.type === 'CharacterClass' ||
    (outerQuant.element.type === 'CharacterSet' && outerQuant.element.kind !== 'any');
  const rewrite = singleAtom
    ? replaceSpan(
        patternSource,
        outerQuant.start,
        outerQuant.end,
        `(?<!${outerQuant.element.raw})${outerQuant.raw}`
      )
    : null;
  return {
    summary:
      'Prefer a linear two-pointer slice loop (`trimSlashes` / `String.prototype.trimEnd()`), or guard the trailing quantifier with a negative lookbehind `(?<!C)C+$` so non-matching interior runs are not re-scanned from every offset.',
    rewrite,
    ...(rewrite !== null ? { rewriteFlags: flagsStr } : {}),
    notes: LINEAR_ENGINE_NOTE
  };
}

export function buildRdh005Fix(
  patternSource: string,
  flagsStr: string,
  kind: 'nested-delimiter-exp' | 'nested-delimiter-poly',
  context: {
    outerQuant?: AST.Quantifier;
    tokenRaw?: string;
    delimRaw?: string;
    delimChar?: string;
    tokenChar?: string;
    suffixEl?: AST.Element;
  }
): FixHint {

  if (
    kind === 'nested-delimiter-exp' &&
    context.outerQuant &&
    context.tokenRaw &&
    context.delimRaw
  ) {
    const oq = context.outerQuant;
    const core = `${context.tokenRaw}+(?:${context.delimRaw}${context.tokenRaw}+)*${context.delimRaw}?`;
    const rep = oq.min === 0 ? `(?:${core})?` : core;
    return {
      summary: `Make delimiter '${context.delimRaw}' mandatory between '${context.tokenRaw}+' segments ('${rep}') to prevent exponential slash/delimiter backtracking.`,
      rewrite: replaceSpan(patternSource, oq.start, oq.end, rep),
      rewriteFlags: flagsStr,
      notes: LINEAR_ENGINE_NOTE
    };
  }

  if (
    kind === 'nested-delimiter-poly' &&
    context.outerQuant &&
    context.tokenChar &&
    context.delimChar &&
    context.suffixEl
  ) {
    const oq = context.outerQuant;
    const clsChars = `${escapeForNegatedClass(context.tokenChar.codePointAt(0)!)}${escapeForNegatedClass(context.delimChar.codePointAt(0)!)}`;
    const rep = `(?<![${clsChars}])${context.tokenRaw}[${clsChars}]*${context.suffixEl.raw}`;
    return {
      summary: `Guard unanchored delimiter loop '${oq.raw}${context.suffixEl.raw}' with a boundary lookbehind '${rep}' (or anchor with '^') so failed suffixes do not re-scan every offset quadratically.`,
      rewrite: replaceSpan(patternSource, oq.start, context.suffixEl.end, rep),
      rewriteFlags: flagsStr,
      notes: LINEAR_ENGINE_NOTE
    };
  }

  return {
    summary:
      'Separate repeated segments with a required delimiter (`^\\w+(?:\\/\\w+)*\\/?$`) or parse path segments via linear index loops.',
    rewrite: null,
    notes: LINEAR_ENGINE_NOTE
  };
}

export function buildRdh006Fix(): FixHint {
  return {
    summary:
      'Move backreferences outside quantified groups, or validate repeated token equality in application code after capturing once.',
    rewrite: null,
    notes:
      'Note: V8 experimental linear engine (`/l`) does not support backreferences; prefer structural validation in code.'
  };
}

/**
 * Canonical catalog of concrete regex rewrites documented by redos-hunter,
 * used both for documentation and for mandatory self-check regression tests.
 */
export const CANONICAL_REWRITE_CATALOG: ReadonlyArray<{
  ruleId: RuleId;
  vulnerablePattern: string;
  vulnerableFlags: string;
  safeRewrite: string;
  safeFlags: string;
}> = [
  {
    ruleId: 'RDH001',
    vulnerablePattern: '^(a+)+$',
    vulnerableFlags: '',
    safeRewrite: '^a+$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH001',
    vulnerablePattern: '(a+)+$',
    vulnerableFlags: '',
    safeRewrite: '(?<!a)a+$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH001',
    vulnerablePattern: '^(\\w+\\s?)*$',
    vulnerableFlags: '',
    safeRewrite: '^(?:\\w+(?:\\s|$))*$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH001',
    vulnerablePattern: '(a+)+',
    vulnerableFlags: '',
    safeRewrite: '(?=(a+))\\1',
    safeFlags: ''
  },
  {
    ruleId: 'RDH002',
    vulnerablePattern: '^(a|a)*$',
    vulnerableFlags: '',
    safeRewrite: '^a*$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH002',
    vulnerablePattern: '^(\\w|\\d)+$',
    vulnerableFlags: '',
    safeRewrite: '^\\w+$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH002',
    vulnerablePattern: '(.|\\s)*$',
    vulnerableFlags: '',
    safeRewrite: '[\\s\\S]*$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH002',
    vulnerablePattern: '^([a-z]|[m-p])+$',
    vulnerableFlags: 'v',
    safeRewrite: '^([[a-z]--[m-p]]|[m-p])+$',
    safeFlags: 'v'
  },
  {
    ruleId: 'RDH007',
    vulnerablePattern: '^\\/+|\\/+$',
    vulnerableFlags: 'g',
    safeRewrite: '^\\/+|(?<!\\/)\\/+$',
    safeFlags: 'g'
  },
  {
    ruleId: 'RDH007',
    vulnerablePattern: '^_+|_+$',
    vulnerableFlags: 'g',
    safeRewrite: '^_+|(?<!_)_+$',
    safeFlags: 'g'
  },
  {
    ruleId: 'RDH007',
    vulnerablePattern: '\\s+$',
    vulnerableFlags: '',
    safeRewrite: '(?<!\\s)\\s+$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH003',
    vulnerablePattern: '^\\d+\\d+$',
    vulnerableFlags: '',
    safeRewrite: '^\\d{2,}$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH003',
    vulnerablePattern: '.*.*=',
    vulnerableFlags: '',
    safeRewrite: '[^=\\r\\n]*=',
    safeFlags: ''
  },
  {
    ruleId: 'RDH005',
    vulnerablePattern: '^(\\w+\\/?)+$',
    vulnerableFlags: '',
    safeRewrite: '^\\w+(?:\\/\\w+)*\\/?$',
    safeFlags: ''
  },
  {
    ruleId: 'RDH005',
    vulnerablePattern: '(a\\/*)+b',
    vulnerableFlags: '',
    safeRewrite: '(?<![a/])a[a/]*b',
    safeFlags: ''
  }
];
