import { RegExpParser, type AST } from '@eslint-community/regexpp';
import {
  applyModifiers,
  characterClassToSet,
  characterSetNodeToSet,
  EMPTY_SET,
  expandIgnoreCase,
  expressionCharacterClassToSet,
  formatIntervalSummary,
  fullSet,
  intersectSets,
  isSubset,
  pickNonMatchingString,
  pickWitnessString,
  setContains,
  setsEqual,
  setsOverlap,
  singletonSet,
  unionSets,
  type CodePointSet,
  type EffectiveFlags
} from './charSet.js';
import { computeFingerprint } from './fingerprint.js';
import {
  buildRdh001Fix,
  buildRdh002Fix,
  buildRdh003Fix,
  buildRdh005Fix,
  buildRdh006Fix,
  buildRdh007Fix
} from './fixHints.js';
import type {
  AttackSpec,
  ExplainResult,
  FixHint,
  RedosFinding,
  RuleId,
  Severity
} from '../types.js';

const parser = new RegExpParser({ ecmaVersion: 2025 });

const DELIMITER_CODE_POINTS = new Set<number>([
  0x2f, // '/'
  0x5c // '\\'
]);

interface SubtreeSummary {
  canMatchEmptyMidString: boolean;
  minLength: number;
  maxLength: number;
  firstChars: CodePointSet;
  lastChars: CodePointSet;
  allChars: CodePointSet;
  sample: string;
}

function escapePreview(s: string, maxLen = 48): string {
  const json = JSON.stringify(s);
  if (json.length <= maxLen) {
    return json;
  }
  return `${json.slice(0, maxLen - 4)}..."`;
}

function makeAttackSpec(
  prefix: string,
  pump: string,
  suffix: string,
  complexity: 'exp' | 'poly'
): AttackSpec {
  const recommendedRepetitions = complexity === 'exp' ? 24 : 8000;
  const parts: string[] = [];
  if (prefix.length > 0) {
    parts.push(escapePreview(prefix, 24));
  }
  parts.push(`${escapePreview(pump, 24)}.repeat(${recommendedRepetitions})`);
  if (suffix.length > 0) {
    parts.push(escapePreview(suffix, 24));
  }
  return {
    prefix,
    pump,
    suffix,
    recommendedRepetitions,
    preview: parts.join(' + ')
  };
}

/**
 * Detects the JS atomic group emulation idiom:
 * `(?=(...))` (`LookaheadAssertion` negate=false with a single `CapturingGroup` G)
 * immediately followed in the same `Alternative` by `\k` (`Backreference` resolved === G).
 */
function findAtomicEmulationPairs(alt: AST.Alternative): {
  atomicLookaheads: Set<AST.LookaheadAssertion>;
  atomicBackrefs: Set<AST.Backreference>;
} {
  const atomicLookaheads = new Set<AST.LookaheadAssertion>();
  const atomicBackrefs = new Set<AST.Backreference>();

  for (let i = 0; i + 1 < alt.elements.length; i++) {
    const cur = alt.elements[i]!;
    const next = alt.elements[i + 1]!;
    if (
      cur.type === 'Assertion' &&
      cur.kind === 'lookahead' &&
      !cur.negate &&
      cur.alternatives.length === 1 &&
      cur.alternatives[0]!.elements.length === 1 &&
      cur.alternatives[0]!.elements[0]!.type === 'CapturingGroup' &&
      next.type === 'Backreference' &&
      !next.ambiguous &&
      next.resolved === cur.alternatives[0]!.elements[0]!
    ) {
      atomicLookaheads.add(cur);
      atomicBackrefs.add(next);
    }
  }
  return { atomicLookaheads, atomicBackrefs };
}

function summarizeElement(el: AST.Element, flags: EffectiveFlags): SubtreeSummary {
  switch (el.type) {
    case 'Assertion': {
      // Zero-width assertions consume 0 chars.
      // Crucial semantic rule: `$` (`kind === 'end'`) without `m` (`multiline`) CANNOT match mid-string
      // before another non-empty token! So `(?:\s|$)` cannot match empty mid-string!
      const canEmptyMid = el.kind === 'end' && !flags.multiline ? false : true;
      return {
        canMatchEmptyMidString: canEmptyMid,
        minLength: 0,
        maxLength: 0,
        firstChars: EMPTY_SET,
        lastChars: EMPTY_SET,
        allChars: EMPTY_SET,
        sample: ''
      };
    }
    case 'Character': {
      const s = flags.ignoreCase
        ? expandIgnoreCase(singletonSet(el.value), flags)
        : singletonSet(el.value);
      const ch = pickWitnessString(s, flags) ?? String.fromCodePoint(el.value);
      return {
        canMatchEmptyMidString: false,
        minLength: 1,
        maxLength: 1,
        firstChars: s,
        lastChars: s,
        allChars: s,
        sample: ch
      };
    }
    case 'CharacterSet': {
      const s = characterSetNodeToSet(el, flags);
      const ch = pickWitnessString(s, flags) ?? 'a';
      return {
        canMatchEmptyMidString: false,
        minLength: 1,
        maxLength: 1,
        firstChars: s,
        lastChars: s,
        allChars: s,
        sample: ch
      };
    }
    case 'CharacterClass': {
      const s = characterClassToSet(el, flags);
      const ch = pickWitnessString(s, flags) ?? 'a';
      return {
        canMatchEmptyMidString: false,
        minLength: 1,
        maxLength: 1,
        firstChars: s,
        lastChars: s,
        allChars: s,
        sample: ch
      };
    }
    case 'ExpressionCharacterClass': {
      const s = expressionCharacterClassToSet(el, flags);
      const ch = pickWitnessString(s, flags) ?? 'a';
      return {
        canMatchEmptyMidString: false,
        minLength: 1,
        maxLength: 1,
        firstChars: s,
        lastChars: s,
        allChars: s,
        sample: ch
      };
    }
    case 'Backreference': {
      if (!el.ambiguous) {
        const refSummary = summarizeAlternatives(el.resolved.alternatives, flags);
        return refSummary;
      }
      const firstGroup = el.resolved[0];
      if (firstGroup) {
        return summarizeAlternatives(firstGroup.alternatives, flags);
      }
      return {
        canMatchEmptyMidString: true,
        minLength: 0,
        maxLength: Infinity,
        firstChars: EMPTY_SET,
        lastChars: EMPTY_SET,
        allChars: EMPTY_SET,
        sample: ''
      };
    }
    case 'Quantifier': {
      if (el.max === 0) {
        return {
          canMatchEmptyMidString: true,
          minLength: 0,
          maxLength: 0,
          firstChars: EMPTY_SET,
          lastChars: EMPTY_SET,
          allChars: EMPTY_SET,
          sample: ''
        };
      }
      const inner = summarizeElement(el.element, flags);
      const minLen = inner.minLength * el.min;
      const maxLen =
        inner.maxLength === 0
          ? 0
          : el.max === Infinity || inner.maxLength === Infinity
            ? Infinity
            : inner.maxLength * el.max;
      return {
        canMatchEmptyMidString: el.min === 0 || inner.canMatchEmptyMidString,
        minLength: minLen,
        maxLength: maxLen,
        firstChars: inner.firstChars,
        lastChars: inner.lastChars,
        allChars: inner.allChars,
        sample: inner.sample.repeat(Math.min(el.min, 4))
      };
    }
    case 'Group': {
      const nextFlags = applyModifiers(flags, el.modifiers);
      return summarizeAlternatives(el.alternatives, nextFlags);
    }
    case 'CapturingGroup': {
      return summarizeAlternatives(el.alternatives, flags);
    }
  }
}

function summarizeAlternative(alt: AST.Alternative, flags: EffectiveFlags): SubtreeSummary {
  const { atomicLookaheads } = findAtomicEmulationPairs(alt);
  const summaries: SubtreeSummary[] = [];

  for (let i = 0; i < alt.elements.length; i++) {
    const el = alt.elements[i]!;
    if (el.type === 'Assertion' && el.kind === 'lookahead' && atomicLookaheads.has(el)) {
      // Paired `\k` immediately follows and carries the actual consumed characters
      continue;
    }
    summaries.push(summarizeElement(el, flags));
  }

  let canAllEmpty = true;
  let minLength = 0;
  let maxLength = 0;
  let firstChars: CodePointSet = EMPTY_SET;
  let allChars: CodePointSet = EMPTY_SET;
  let sample = '';

  for (const s of summaries) {
    if (canAllEmpty) {
      firstChars = unionSets(firstChars, s.firstChars);
    }
    if (!s.canMatchEmptyMidString) {
      canAllEmpty = false;
    }
    minLength += s.minLength;
    maxLength =
      maxLength === Infinity || s.maxLength === Infinity ? Infinity : maxLength + s.maxLength;
    allChars = unionSets(allChars, s.allChars);
    if (sample.length < 32) {
      sample += s.sample;
    }
  }

  let lastChars: CodePointSet = EMPTY_SET;
  let suffixCanEmpty = true;
  for (let i = summaries.length - 1; i >= 0; i--) {
    const s = summaries[i]!;
    if (suffixCanEmpty) {
      lastChars = unionSets(lastChars, s.lastChars);
    }
    if (!s.canMatchEmptyMidString) {
      suffixCanEmpty = false;
    }
  }

  return {
    canMatchEmptyMidString: canAllEmpty,
    minLength,
    maxLength,
    firstChars,
    lastChars,
    allChars,
    sample
  };
}

function summarizeAlternatives(
  alts: ReadonlyArray<AST.Alternative>,
  flags: EffectiveFlags
): SubtreeSummary {
  if (alts.length === 0) {
    return {
      canMatchEmptyMidString: true,
      minLength: 0,
      maxLength: 0,
      firstChars: EMPTY_SET,
      lastChars: EMPTY_SET,
      allChars: EMPTY_SET,
      sample: ''
    };
  }
  let canEmpty = false;
  let minLen = Infinity;
  let maxLen = 0;
  let first: CodePointSet = EMPTY_SET;
  let last: CodePointSet = EMPTY_SET;
  let all: CodePointSet = EMPTY_SET;
  let bestSample: string | null = null;

  for (const alt of alts) {
    const s = summarizeAlternative(alt, flags);
    if (s.canMatchEmptyMidString) {
      canEmpty = true;
    }
    if (s.minLength < minLen) {
      minLen = s.minLength;
    }
    if (s.maxLength > maxLen) {
      maxLen = s.maxLength;
    }
    first = unionSets(first, s.firstChars);
    last = unionSets(last, s.lastChars);
    all = unionSets(all, s.allChars);
    if (bestSample === null || (bestSample === '' && s.sample !== '')) {
      bestSample = s.sample;
    }
  }

  return {
    canMatchEmptyMidString: canEmpty,
    minLength: minLen === Infinity ? 0 : minLen,
    maxLength: maxLen,
    firstChars: first,
    lastChars: last,
    allChars: all,
    sample: bestSample ?? ''
  };
}

function alternativeStartsWithCaret(alt: AST.Alternative): boolean {
  for (const el of alt.elements) {
    if (el.type === 'Assertion') {
      if (el.kind === 'start') {
        return true;
      }
      continue;
    }
    if (el.type === 'Group' || el.type === 'CapturingGroup') {
      return el.alternatives.every(alternativeStartsWithCaret);
    }
    return false;
  }
  return false;
}

function alternativeEndsWithDollar(alt: AST.Alternative): boolean {
  for (let i = alt.elements.length - 1; i >= 0; i--) {
    const el = alt.elements[i]!;
    if (el.type === 'Assertion') {
      if (el.kind === 'end') {
        return true;
      }
      continue;
    }
    if (el.type === 'Group' || el.type === 'CapturingGroup') {
      return el.alternatives.every(alternativeEndsWithDollar);
    }
    return false;
  }
  return false;
}

function patternIsStartAnchored(pattern: AST.Pattern, flags: EffectiveFlags): boolean {
  if (flags.multiline) {
    return false;
  }
  return pattern.alternatives.length > 0 && pattern.alternatives.every(alternativeStartsWithCaret);
}

/**
 * Checks if a subtree contains any variable-count quantifier (`max > min` and `max >= 2`, or two optional quantifiers overlapping),
 * ignoring atomic lookahead groups `(?=(...))\k` whose inner backtracking is discarded on lookahead exit.
 */
function collectActiveInnerQuantifiers(
  el: AST.Element,
  flags: EffectiveFlags,
  out: Array<{ quant: AST.Quantifier; flags: EffectiveFlags }>
): void {
  if (el.type === 'Assertion') {
    // Lookarounds discard internal backtrack stacks once matched; do not treat quantifiers inside lookarounds as outer-loop star-height
    return;
  }
  if (el.type === 'Quantifier') {
    out.push({ quant: el, flags });
    collectActiveInnerQuantifiers(el.element, flags, out);
    return;
  }
  if (el.type === 'Group') {
    const nextFlags = applyModifiers(flags, el.modifiers);
    for (const alt of el.alternatives) {
      const { atomicLookaheads } = findAtomicEmulationPairs(alt);
      for (const child of alt.elements) {
        if (child.type === 'Assertion' && child.kind === 'lookahead' && atomicLookaheads.has(child)) {
          continue;
        }
        collectActiveInnerQuantifiers(child, nextFlags, out);
      }
    }
    return;
  }
  if (el.type === 'CapturingGroup') {
    for (const alt of el.alternatives) {
      const { atomicLookaheads } = findAtomicEmulationPairs(alt);
      for (const child of alt.elements) {
        if (child.type === 'Assertion' && child.kind === 'lookahead' && atomicLookaheads.has(child)) {
          continue;
        }
        collectActiveInnerQuantifiers(child, flags, out);
      }
    }
  }
}

function containsDelimiterCodePoint(set: CodePointSet): boolean {
  for (const cp of DELIMITER_CODE_POINTS) {
    if (setContains(set, cp)) {
      return true;
    }
  }
  return false;
}

function isRepeatableLoop(q: AST.Quantifier): boolean {
  return q.max === Infinity || q.max >= 8;
}

function pickSuffixFailingAfter(
  outerNode: AST.Element,
  outerAllChars: CodePointSet,
  flags: EffectiveFlags
): string {
  // Walk up to find what element follows `outerNode` in its parent Alternative
  let cur: AST.Node = outerNode;
  while (cur.parent && cur.parent.type !== 'Pattern') {
    if (cur.parent.type === 'Alternative') {
      const alt = cur.parent;
      const idx = alt.elements.indexOf(cur as AST.Element);
      if (idx >= 0 && idx + 1 < alt.elements.length) {
        // Summarize remaining suffix of this alternative
        let canRestEmpty = true;
        let nextFirst: CodePointSet = EMPTY_SET;
        let restSample = '';
        for (let k = idx + 1; k < alt.elements.length; k++) {
          const remEl = alt.elements[k]!;
          const s = summarizeElement(remEl, flags);
          if (canRestEmpty) {
            nextFirst = unionSets(nextFirst, s.firstChars);
          }
          if (!s.canMatchEmptyMidString) {
            canRestEmpty = false;
          }
          restSample += s.sample;
        }
        const excluded = unionSets(outerAllChars, nextFirst);
        return pickNonMatchingString(excluded, flags);
        void restSample;
      }
    }
    cur = cur.parent;
  }
  return pickNonMatchingString(outerAllChars, flags);
}

function buildLeadingPrefixSample(target: AST.Node, rootPattern: AST.Pattern, baseFlags: EffectiveFlags): string {
  // Collect required leading sample before `target` in its top-level alternative
  const chain: AST.Node[] = [];
  let cur: AST.Node | null = target;
  while (cur && cur !== rootPattern) {
    chain.push(cur);
    cur = cur.parent;
  }
  chain.reverse();

  let prefix = '';
  const flags = baseFlags;
  for (let i = 0; i < chain.length; i++) {
    const node = chain[i]!;
    if (node.type === 'Alternative') {
      const nextChild = chain[i + 1];
      for (const el of node.elements) {
        if (el === nextChild) {
          break;
        }
        prefix += summarizeElement(el, flags).sample;
      }
    }
  }
  return prefix;
}

export interface AnalyzePatternOptions {
  file?: string;
  line?: number;
  column?: number;
}

export function parseRegexAst(
  patternSource: string,
  flagsStr: string
): { patternAst: AST.Pattern; flagsAst: AST.Flags; effectiveFlags: EffectiveFlags } {
  const flagsAst = parser.parseFlags(flagsStr);
  const patternAst = parser.parsePattern(patternSource, 0, patternSource.length, {
    unicode: flagsAst.unicode,
    unicodeSets: flagsAst.unicodeSets
  });
  const effectiveFlags: EffectiveFlags = {
    unicode: flagsAst.unicode,
    unicodeSets: flagsAst.unicodeSets,
    ignoreCase: flagsAst.ignoreCase,
    dotAll: flagsAst.dotAll,
    multiline: flagsAst.multiline
  };
  return { patternAst, flagsAst, effectiveFlags };
}

export function severityForComplexity(complexity: 'exp' | 'poly' | 'warning'): Severity {
  return complexity === 'exp' ? 'high' : 'medium';
}

export function analyzePattern(
  patternSource: string,
  flagsStr = '',
  options: AnalyzePatternOptions = {}
): RedosFinding[] {
  const file = options.file ?? '<inline>';
  const line = options.line ?? 1;
  const column = options.column ?? 1;

  let parsed: ReturnType<typeof parseRegexAst>;
  try {
    parsed = parseRegexAst(patternSource, flagsStr);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const span = { start: 0, end: patternSource.length };
    return [
      {
        ruleId: 'RDH904',
        severity: 'low',
        complexity: 'info',
        message: `Invalid regular expression syntax: ${msg}`,
        file,
        line,
        column,
        pattern: patternSource,
        flags: flagsStr,
        span,
        fingerprint: computeFingerprint({
          ruleId: 'RDH904',
          file,
          pattern: patternSource,
          flags: flagsStr,
          span
        })
      }
    ];
  }

  const { patternAst, effectiveFlags } = parsed;
  const findings: RedosFinding[] = [];
  const emittedKeys = new Set<string>();
  const flaggedQuantifiers = new Set<AST.Quantifier>();

  function emitFinding(params: {
    ruleId: RuleId;
    complexity: 'exp' | 'poly' | 'warning';
    message: string;
    span: { start: number; end: number };
    overlapSummary?: string;
    attack?: AttackSpec;
    fix?: FixHint;
  }): void {
    const dedupKey = `${params.ruleId}:${params.span.start}:${params.span.end}`;
    if (emittedKeys.has(dedupKey)) {
      return;
    }
    emittedKeys.add(dedupKey);
    const fingerprint = computeFingerprint({
      ruleId: params.ruleId,
      file,
      pattern: patternSource,
      flags: flagsStr,
      span: params.span
    });
    findings.push({
      ruleId: params.ruleId,
      severity: severityForComplexity(params.complexity),
      complexity: params.complexity,
      message: params.message,
      file,
      line,
      column,
      pattern: patternSource,
      flags: flagsStr,
      span: params.span,
      ...(params.overlapSummary !== undefined ? { overlapSummary: params.overlapSummary } : {}),
      ...(params.attack !== undefined ? { attack: params.attack } : {}),
      ...(params.fix !== undefined ? { fix: params.fix } : {}),
      fingerprint
    });
  }

  const isWholePatternStartAnchored = patternIsStartAnchored(patternAst, effectiveFlags);

  // -------------------------------------------------------------------------
  // Pass 1: Top-level RDH005 unanchored end-anchored quantifiers
  // Examples: `/^\/+|\/+$/g` (repo-atlas trimSlashes bug), `/\s+$/`, `/\/+$/`
  // -------------------------------------------------------------------------
  let startAnchoredBranchFirstChars: CodePointSet = EMPTY_SET;
  for (const topAlt of patternAst.alternatives) {
    if (alternativeStartsWithCaret(topAlt)) {
      const s = summarizeAlternative(topAlt, effectiveFlags);
      startAnchoredBranchFirstChars = unionSets(startAnchoredBranchFirstChars, s.firstChars);
    }
  }

  for (const topAlt of patternAst.alternatives) {
    if (!alternativeStartsWithCaret(topAlt) && alternativeEndsWithDollar(topAlt)) {
      // Find first non-assertion element and track any leading negative lookbehind guard `(?<!X)`
      let firstQuant: AST.Quantifier | null = null;
      let hasFixedPrefix = false;
      let negLookbehindExcluded: CodePointSet = EMPTY_SET;
      for (const el of topAlt.elements) {
        if (el.type === 'Assertion') {
          if (el.kind === 'end') {
            break;
          }
          if (el.kind === 'lookbehind' && el.negate) {
            const lbSummary = summarizeAlternatives(el.alternatives, effectiveFlags);
            if (lbSummary.maxLength === 1) {
              negLookbehindExcluded = unionSets(negLookbehindExcluded, lbSummary.firstChars);
            }
          }
          continue;
        }
        if (el.type === 'Quantifier' && isRepeatableLoop(el)) {
          firstQuant = el;
          break;
        }
        const s = summarizeElement(el, effectiveFlags);
        if (!s.canMatchEmptyMidString) {
          hasFixedPrefix = true;
          break;
        }
      }

      if (!hasFixedPrefix && firstQuant !== null) {
        // Confirm all remaining elements after `firstQuant` up to `$` can match empty
        const qIdx = topAlt.elements.indexOf(firstQuant);
        let restAllNullable = true;
        for (let k = qIdx + 1; k < topAlt.elements.length; k++) {
          const el = topAlt.elements[k]!;
          if (el.type === 'Assertion' && el.kind === 'end') {
            continue;
          }
          if (!summarizeElement(el, effectiveFlags).canMatchEmptyMidString) {
            restAllNullable = false;
            break;
          }
        }

        const nestedInsideFirst: Array<{ quant: AST.Quantifier; flags: EffectiveFlags }> = [];
        collectActiveInnerQuantifiers(firstQuant.element, effectiveFlags, nestedInsideFirst);
        const hasOverlappingAltInside =
          (firstQuant.element.type === 'Group' || firstQuant.element.type === 'CapturingGroup') &&
          firstQuant.element.alternatives.length >= 2;

        const qSummary = summarizeElement(firstQuant, effectiveFlags);
        const matchesUniversal = setsEqual(qSummary.allChars, fullSet(effectiveFlags));
        const guardedByNegLookbehind =
          qSummary.firstChars.length > 0 && isSubset(qSummary.firstChars, negLookbehindExcluded);

        if (
          restAllNullable &&
          !guardedByNegLookbehind &&
          nestedInsideFirst.length === 0 &&
          !hasOverlappingAltInside &&
          !matchesUniversal &&
          qSummary.firstChars.length > 0
        ) {
          const pump = pickWitnessString(qSummary.firstChars, effectiveFlags) ?? '/';
          const excludedForPrefix = unionSets(startAnchoredBranchFirstChars, qSummary.firstChars);
          const prefix =
            patternAst.alternatives.length > 1
              ? pickNonMatchingString(excludedForPrefix, effectiveFlags)
              : '';
          const suffix = pickNonMatchingString(qSummary.allChars, effectiveFlags);

          flaggedQuantifiers.add(firstQuant);
          emitFinding({
            ruleId: 'RDH007',
            complexity: 'poly',
            message: `Unanchored end-anchored quantifier '${topAlt.raw}' scans from every character offset in non-matching runs (quadratic O(n^2) backtracking).`,
            span: { start: topAlt.start, end: topAlt.end },
            overlapSummary: `Repeated end-anchored set ${formatIntervalSummary(qSummary.firstChars)} without leading '^'`,
            attack: makeAttackSpec(prefix, pump, suffix, 'poly'),
            fix: buildRdh007Fix(patternSource, flagsStr, firstQuant)
          });
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Pass 2: Recursive walk for RDH002, RDH005 (nested delimiter), RDH001, RDH006, RDH003
  // -------------------------------------------------------------------------
  function checkQuantifierNode(quant: AST.Quantifier, flags: EffectiveFlags, insideQuantDepth: number): void {
    if (!isRepeatableLoop(quant)) {
      return;
    }

    const bodyEl = quant.element;
    const bodyFlags =
      bodyEl.type === 'Group' ? applyModifiers(flags, bodyEl.modifiers) : flags;

    // 2A. RDH002: Overlapping alternation directly inside quantified group `(alt1|alt2)+`
    if (
      (bodyEl.type === 'Group' || bodyEl.type === 'CapturingGroup') &&
      bodyEl.alternatives.length >= 2
    ) {
      const altSummaries = bodyEl.alternatives.map((a) => summarizeAlternative(a, bodyFlags));
      let foundOverlap: {
        i: number;
        j: number;
        overlapSet: CodePointSet;
        witness: string;
      } | null = null;

      for (let i = 0; i < altSummaries.length && !foundOverlap; i++) {
        for (let j = i + 1; j < altSummaries.length; j++) {
          const s1 = altSummaries[i]!;
          const s2 = altSummaries[j]!;
          const inter = intersectSets(s1.firstChars, s2.firstChars);
          if (inter.length === 0) {
            continue;
          }
          // Check if both branches can match a shared single char OR one branch can match a prefix that splits across outer iterations
          const bothMatchSingleChar = s1.minLength <= 1 && s2.minLength <= 1;
          const prefixCrossIteration =
            s1.sample === s2.sample ||
            (s1.minLength === 1 && s2.sample.startsWith(s1.sample) &&
              altSummaries.some((s3) => s3.sample === s2.sample.slice(s1.sample.length))) ||
            (s2.minLength === 1 && s1.sample.startsWith(s2.sample) &&
              altSummaries.some((s3) => s3.sample === s1.sample.slice(s2.sample.length)));

          if (bothMatchSingleChar || prefixCrossIteration) {
            const w =
              bothMatchSingleChar
                ? (pickWitnessString(inter, bodyFlags) ?? 'a')
                : s1.sample.length >= s2.sample.length
                  ? s1.sample
                  : s2.sample;
            foundOverlap = { i, j, overlapSet: inter, witness: w };
            break;
          }
        }
      }

      if (foundOverlap) {
        const wholeSummary = summarizeElement(quant, flags);
        const prefix = buildLeadingPrefixSample(quant, patternAst, effectiveFlags);
        const suffix = pickSuffixFailingAfter(quant, wholeSummary.allChars, flags);
        flaggedQuantifiers.add(quant);

        emitFinding({
          ruleId: 'RDH002',
          complexity: 'exp',
          message: `Overlapping alternation branches '${bodyEl.alternatives[foundOverlap.i]!.raw}' and '${bodyEl.alternatives[foundOverlap.j]!.raw}' inside quantifier '${quant.raw}' cause exponential backtracking.`,
          span: { start: quant.start, end: quant.end },
          overlapSummary: `Shared code points: ${formatIntervalSummary(foundOverlap.overlapSet)}`,
          attack: makeAttackSpec(prefix, foundOverlap.witness, suffix, 'exp'),
          fix: buildRdh002Fix(patternSource, flagsStr, quant, bodyFlags)
        });
      }
    }

    // 2B. RDH005 & RDH001: Star-height > 1 nested quantifiers
    const innerQuants: Array<{ quant: AST.Quantifier; flags: EffectiveFlags }> = [];
    collectActiveInnerQuantifiers(bodyEl, bodyFlags, innerQuants);

    if (innerQuants.length > 0 && !flaggedQuantifiers.has(quant)) {
      const bodySummary = summarizeElement(bodyEl, bodyFlags);
      const crossOverlap = intersectSets(bodySummary.lastChars, bodySummary.firstChars);

      // Check if an inner quantifier contains a slash/path delimiter (`/` or `\`)
      const slashInner = innerQuants.find(({ quant: iq, flags: iflags }) => {
        const s = summarizeElement(iq.element, iflags);
        return containsDelimiterCodePoint(s.allChars);
      });

      // Determine whether a single iteration of `bodyEl` can consume >= 2 copies of the overlapping witness
      // (which creates 2^n partition ambiguity across outer iterations!)
      let hasMultiMatchInner = false;
      for (const { quant: iq, flags: iflags } of innerQuants) {
        if (iq.max >= 2) {
          const iqSummary = summarizeElement(iq.element, iflags);
          if (setsOverlap(iqSummary.allChars, crossOverlap)) {
            hasMultiMatchInner = true;
            break;
          }
        }
      }
      // Also check two distinct optional quantifiers inside `bodyEl` matching the same witness (e.g. `(a?a?)+`)
      if (!hasMultiMatchInner && innerQuants.length >= 2 && crossOverlap.length > 0) {
        let matchingOptionals = 0;
        for (const { quant: iq, flags: iflags } of innerQuants) {
          if (iq.max >= 1 && setsOverlap(summarizeElement(iq.element, iflags).allChars, crossOverlap)) {
            matchingOptionals++;
          }
        }
        if (matchingOptionals >= 2) {
          hasMultiMatchInner = true;
        }
      }

      if (crossOverlap.length > 0 && hasMultiMatchInner) {
        const pump = pickWitnessString(crossOverlap, bodyFlags) ?? 'a';
        const wholeSummary = summarizeElement(quant, flags);
        const prefix = buildLeadingPrefixSample(quant, patternAst, effectiveFlags);
        const suffix = pickSuffixFailingAfter(quant, wholeSummary.allChars, flags);

        if (slashInner) {
          // RDH005 exponential nested delimiter loop (e.g. `^(\w+\/?)+$`)
          let tokenRaw: string | undefined;
          let delimRaw: string | undefined;
          if (
            (bodyEl.type === 'Group' || bodyEl.type === 'CapturingGroup') &&
            bodyEl.alternatives.length === 1 &&
            bodyEl.alternatives[0]!.elements.length === 2
          ) {
            const e0 = bodyEl.alternatives[0]!.elements[0]!;
            const e1 = bodyEl.alternatives[0]!.elements[1]!;
            if (
              e0.type === 'Quantifier' &&
              e0.min >= 1 &&
              e0.max === Infinity &&
              e1.type === 'Quantifier' &&
              e1.min === 0 &&
              e1.max <= 1
            ) {
              const s0 = summarizeElement(e0.element, bodyFlags);
              const s1 = summarizeElement(e1.element, bodyFlags);
              if (!setsOverlap(s0.allChars, s1.allChars)) {
                tokenRaw = e0.element.raw;
                delimRaw = e1.element.raw;
              }
            }
          }

          flaggedQuantifiers.add(quant);
          emitFinding({
            ruleId: 'RDH005',
            complexity: 'exp',
            message: `Nested optional slash/delimiter inside quantified group '${quant.raw}' allows exponential O(2^n) backtracking when delimiters are omitted.`,
            span: { start: quant.start, end: quant.end },
            overlapSummary: `Cross-iteration overlap on ${formatIntervalSummary(crossOverlap)}`,
            attack: makeAttackSpec(prefix, pump, suffix, 'exp'),
            fix: buildRdh005Fix(patternSource, flagsStr, 'nested-delimiter-exp', {
              outerQuant: quant,
              ...(tokenRaw !== undefined ? { tokenRaw } : {}),
              ...(delimRaw !== undefined ? { delimRaw } : {})
            })
          });
        } else {
          // RDH001 exponential nested quantifier (e.g. `(a+)+`, `(\w+\s?)*`)
          flaggedQuantifiers.add(quant);
          emitFinding({
            ruleId: 'RDH001',
            complexity: 'exp',
            message: `Nested quantifier '${quant.raw}' (star-height > 1) has cross-iteration overlap causing exponential O(2^n) backtracking.`,
            span: { start: quant.start, end: quant.end },
            overlapSummary: `Inner/outer overlap on ${formatIntervalSummary(crossOverlap)}`,
            attack: makeAttackSpec(prefix, pump, suffix, 'exp'),
            fix: buildRdh001Fix(patternSource, flagsStr, quant, bodyFlags)
          });
        }
      } else if (
        slashInner &&
        !isWholePatternStartAnchored &&
        insideQuantDepth === 0 &&
        (bodyEl.type === 'Group' || bodyEl.type === 'CapturingGroup') &&
        bodyEl.alternatives.length === 1
      ) {
        // RDH005 polynomial unanchored delimiter loop with suffix (e.g. `(a\/*)+b`)
        const parentAlt = quant.parent;
        const qIdx = parentAlt.elements.indexOf(quant);
        const nextEl = qIdx >= 0 ? parentAlt.elements[qIdx + 1] : undefined;
        const hasFailingContinuation =
          nextEl !== undefined &&
          ((nextEl.type === 'Assertion' && nextEl.kind === 'end') ||
            !summarizeElement(nextEl, flags).canMatchEmptyMidString);

        if (hasFailingContinuation) {
          const innerEls = bodyEl.alternatives[0]!.elements;
          let tokenRaw: string | undefined;
          let tokenChar: string | undefined;
          let delimChar: string | undefined;
          let suffixSingleEl: AST.Element | undefined;

          if (
            innerEls.length === 2 &&
            innerEls[0]!.type === 'Character' &&
            innerEls[1] === slashInner.quant &&
            slashInner.quant.min === 0 &&
            slashInner.quant.max === Infinity &&
            slashInner.quant.element.type === 'Character' &&
            nextEl &&
            nextEl.type === 'Character'
          ) {
            const tSet = summarizeElement(innerEls[0]!, bodyFlags).allChars;
            const dSet = summarizeElement(slashInner.quant.element, bodyFlags).allChars;
            const sSet = summarizeElement(nextEl, flags).allChars;
            if (!setsOverlap(unionSets(tSet, dSet), sSet)) {
              tokenRaw = innerEls[0]!.raw;
              tokenChar = String.fromCodePoint(innerEls[0]!.value);
              delimChar = String.fromCodePoint(slashInner.quant.element.value);
              suffixSingleEl = nextEl;
            }
          }

          const delimWitness =
            pickWitnessString(
              summarizeElement(slashInner.quant.element, slashInner.flags).allChars,
              slashInner.flags
            ) ?? '/';
          const pump = `${bodySummary.sample}${delimWitness}`;
          const wholeSummary = summarizeElement(quant, flags);
          const suffix = pickSuffixFailingAfter(quant, wholeSummary.allChars, flags);

          flaggedQuantifiers.add(quant);
          emitFinding({
            ruleId: 'RDH005',
            complexity: 'poly',
            message: `Unanchored delimiter loop '${quant.raw}' re-scans repeated segment runs from every starting position when its trailing match fails (polynomial O(n^2) backtracking).`,
            span: { start: quant.start, end: quant.end },
            overlapSummary: `Unanchored repeated delimiter loop over ${formatIntervalSummary(wholeSummary.allChars)}`,
            attack: makeAttackSpec('', pump, suffix, 'poly'),
            fix: buildRdh005Fix(patternSource, flagsStr, 'nested-delimiter-poly', {
              outerQuant: quant,
              ...(tokenRaw !== undefined ? { tokenRaw } : {}),
              ...(tokenChar !== undefined ? { tokenChar } : {}),
              ...(delimChar !== undefined ? { delimChar } : {}),
              ...(suffixSingleEl !== undefined ? { suffixEl: suffixSingleEl } : {})
            })
          });
        }
      }
    }
  }

  function checkAlternativeAdjacentQuantifiers(alt: AST.Alternative, flags: EffectiveFlags): void {
    const { atomicLookaheads } = findAtomicEmulationPairs(alt);
    const elements = alt.elements;

    for (let i = 0; i < elements.length; i++) {
      const elI = elements[i]!;
      if (elI.type !== 'Quantifier' || !isRepeatableLoop(elI)) {
        continue;
      }
      const sumI = summarizeElement(elI.element, flags);
      if (sumI.lastChars.length === 0) {
        continue;
      }

      for (let j = i + 1; j < elements.length; j++) {
        const elJ = elements[j]!;

        // Check if elJ is another repeatable quantifier while everything in (i+1 .. j-1) could match empty mid-string
        if (elJ.type === 'Quantifier' && isRepeatableLoop(elJ)) {
          const sumJ = summarizeElement(elJ.element, flags);
          const inter = intersectSets(sumI.lastChars, sumJ.firstChars);

          if (inter.length > 0) {
            const witness = pickWitnessString(inter, flags) ?? 'a';
            const combinedChars = unionSets(sumI.allChars, sumJ.allChars);

            // Check what follows `elJ` to construct a failing suffix
            let tailFirstChars: CodePointSet = EMPTY_SET;
            let tailCanEmpty = true;
            for (let k = j + 1; k < elements.length; k++) {
              const tk = elements[k]!;
              if (tk.type === 'Assertion' && tk.kind === 'end') {
                break;
              }
              const ts = summarizeElement(tk, flags);
              if (tailCanEmpty) {
                tailFirstChars = unionSets(tailFirstChars, ts.firstChars);
              }
              if (!ts.canMatchEmptyMidString) {
                tailCanEmpty = false;
              }
            }

            const prefix = buildLeadingPrefixSample(elI, patternAst, effectiveFlags);
            // If there is a required non-empty literal/token tail (like `=` in `.*.*=`), any char failing both or failing the tail triggers full backtracking
            const strictExcluded = unionSets(combinedChars, tailFirstChars);
            let suffix = pickNonMatchingString(strictExcluded, flags);
            if (
              (suffix === '\n' || suffix === '\0') &&
              !tailCanEmpty &&
              tailFirstChars.length > 0
            ) {
              suffix = pickNonMatchingString(tailFirstChars, flags);
            }

            emitFinding({
              ruleId: 'RDH003',
              complexity: 'poly',
              message: `Adjacent overlapping quantifiers '${elI.raw}' and '${elJ.raw}' shift token boundaries polynomially across repeated ${formatIntervalSummary(inter)} runs.`,
              span: { start: elI.start, end: elJ.end },
              overlapSummary: `Adjacent quantifier overlap on ${formatIntervalSummary(inter)}`,
              attack: makeAttackSpec(prefix, witness, suffix, 'poly'),
              fix: buildRdh003Fix(patternSource, flagsStr, alt, i, j, flags)
            });
            // Avoid quadratic duplicate pairs starting from the same `i` once matched
            break;
          }
        }

        // Can `elJ` match empty mid-string so `elI` can touch `elements[j+1]`?
        if (elJ.type === 'Assertion' && elJ.kind === 'lookahead' && atomicLookaheads.has(elJ)) {
          continue;
        }
        const midSummary = summarizeElement(elJ, flags);
        if (!midSummary.canMatchEmptyMidString) {
          break;
        }
      }
    }
  }

  function walkAlternative(alt: AST.Alternative, flags: EffectiveFlags, quantDepth: number): void {
    const { atomicLookaheads, atomicBackrefs } = findAtomicEmulationPairs(alt);

    checkAlternativeAdjacentQuantifiers(alt, flags);

    for (const el of alt.elements) {
      if (el.type === 'Assertion') {
        if (el.kind === 'lookahead' && atomicLookaheads.has(el)) {
          // Still inspect inside the atomic lookahead for its OWN internal nested quantifiers (at depth 0 since lookahead commits!)
          for (const laAlt of el.alternatives) {
            walkAlternative(laAlt, flags, 0);
          }
          continue;
        }
        if (el.kind === 'lookahead' || el.kind === 'lookbehind') {
          for (const laAlt of el.alternatives) {
            walkAlternative(laAlt, flags, 0);
          }
        }
        continue;
      }

      if (el.type === 'Backreference') {
        if (quantDepth > 0 && !atomicBackrefs.has(el)) {
          emitFinding({
            ruleId: 'RDH006',
            complexity: 'warning',
            message: `Backreference '${el.raw}' inside a quantified group disables linear finite-automaton execution and risks super-linear backtracking.`,
            span: { start: el.start, end: el.end },
            fix: buildRdh006Fix()
          });
        }
        continue;
      }

      if (el.type === 'Quantifier') {
        const nextDepth = isRepeatableLoop(el) ? quantDepth + 1 : quantDepth;
        checkQuantifierNode(el, flags, quantDepth);

        if (el.element.type === 'Backreference' && isRepeatableLoop(el)) {
          emitFinding({
            ruleId: 'RDH006',
            complexity: 'warning',
            message: `Quantified backreference '${el.raw}' disables linear finite-automaton execution and can trigger backtracking on repeated captures.`,
            span: { start: el.start, end: el.end },
            fix: buildRdh006Fix()
          });
        } else if (el.element.type === 'Group') {
          const gFlags = applyModifiers(flags, el.element.modifiers);
          for (const gAlt of el.element.alternatives) {
            walkAlternative(gAlt, gFlags, nextDepth);
          }
        } else if (el.element.type === 'CapturingGroup') {
          for (const gAlt of el.element.alternatives) {
            walkAlternative(gAlt, flags, nextDepth);
          }
        } else if (el.element.type === 'Assertion' && el.element.kind === 'lookahead') {
          for (const laAlt of el.element.alternatives) {
            walkAlternative(laAlt, flags, 0);
          }
        }
        continue;
      }

      if (el.type === 'Group') {
        const gFlags = applyModifiers(flags, el.modifiers);
        for (const gAlt of el.alternatives) {
          walkAlternative(gAlt, gFlags, quantDepth);
        }
        continue;
      }

      if (el.type === 'CapturingGroup') {
        for (const gAlt of el.alternatives) {
          walkAlternative(gAlt, flags, quantDepth);
        }
      }
    }
  }

  for (const topAlt of patternAst.alternatives) {
    walkAlternative(topAlt, effectiveFlags, 0);
  }

  return findings;
}

function formatAstOutline(patternAst: AST.Pattern): string[] {
  const lines: string[] = [];

  function walk(node: AST.Alternative | AST.Element, indent: string): void {
    if (lines.length >= 80) {
      if (lines.length === 80) {
        lines.push(`${indent}... (AST truncated)`);
      }
      return;
    }
    if (node.type === 'Alternative') {
      lines.push(`${indent}Alternative "${node.raw}" [${node.start}..${node.end}]`);
      for (const el of node.elements) {
        walk(el, indent + '  ');
      }
      return;
    }
    switch (node.type) {
      case 'Quantifier':
        lines.push(
          `${indent}Quantifier "${node.raw}" (min=${node.min}, max=${node.max === Infinity ? 'Inf' : node.max}, greedy=${node.greedy}) [${node.start}..${node.end}]`
        );
        walk(node.element, indent + '  ');
        break;
      case 'CapturingGroup':
        lines.push(
          `${indent}CapturingGroup${node.name ? `(?<${node.name}>)` : ''} "${node.raw}" [${node.start}..${node.end}]`
        );
        for (const alt of node.alternatives) {
          walk(alt, indent + '  ');
        }
        break;
      case 'Group':
        lines.push(`${indent}Group "${node.raw}" [${node.start}..${node.end}]`);
        for (const alt of node.alternatives) {
          walk(alt, indent + '  ');
        }
        break;
      case 'Assertion':
        lines.push(`${indent}Assertion(${node.kind}) "${node.raw}" [${node.start}..${node.end}]`);
        if (node.kind === 'lookahead' || node.kind === 'lookbehind') {
          for (const alt of node.alternatives) {
            walk(alt, indent + '  ');
          }
        }
        break;
      default:
        lines.push(`${indent}${node.type} "${node.raw}" [${node.start}..${node.end}]`);
        break;
    }
  }

  for (const alt of patternAst.alternatives) {
    walk(alt, '');
  }
  return lines;
}

export function explainPattern(patternSource: string, flagsStr = ''): ExplainResult {
  const { patternAst } = parseRegexAst(patternSource, flagsStr);
  const astSummary = formatAstOutline(patternAst);
  const findings = analyzePattern(patternSource, flagsStr, { file: '<explain>', line: 1, column: 1 });
  return {
    pattern: patternSource,
    flags: flagsStr,
    astSummary,
    findings
  };
}
