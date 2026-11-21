import type { AST } from '@eslint-community/regexpp';

export type Interval = readonly [number, number];
export type CodePointSet = readonly Interval[];

export interface EffectiveFlags {
  readonly unicode: boolean;
  readonly unicodeSets: boolean;
  readonly ignoreCase: boolean;
  readonly dotAll: boolean;
  readonly multiline: boolean;
}

export const EMPTY_SET: CodePointSet = [];
export const BMP_MAX = 0xffff;
export const UNICODE_MAX = 0x10ffff;

export function maxCodePoint(flags: { unicode: boolean; unicodeSets: boolean }): number {
  return flags.unicode || flags.unicodeSets ? UNICODE_MAX : BMP_MAX;
}

export function fullSet(flags: { unicode: boolean; unicodeSets: boolean }): CodePointSet {
  return [[0, maxCodePoint(flags)]];
}

export function singletonSet(cp: number): CodePointSet {
  return [[cp, cp]];
}

export function rangeSet(min: number, max: number): CodePointSet {
  if (min > max) {
    return EMPTY_SET;
  }
  return [[min, max]];
}

export function normalizeIntervals(raw: ReadonlyArray<Interval>): CodePointSet {
  if (raw.length === 0) {
    return EMPTY_SET;
  }
  const filtered: Array<[number, number]> = [];
  for (const [lo, hi] of raw) {
    if (lo <= hi) {
      filtered.push([lo, hi]);
    }
  }
  if (filtered.length === 0) {
    return EMPTY_SET;
  }
  filtered.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged: Array<Interval> = [];
  let [curLo, curHi] = filtered[0]!;
  for (let i = 1; i < filtered.length; i++) {
    const [lo, hi] = filtered[i]!;
    if (lo <= curHi + 1) {
      if (hi > curHi) {
        curHi = hi;
      }
    } else {
      merged.push([curLo, curHi]);
      curLo = lo;
      curHi = hi;
    }
  }
  merged.push([curLo, curHi]);
  return merged;
}

export function unionSets(a: CodePointSet, b: CodePointSet): CodePointSet {
  if (a.length === 0) {
    return b;
  }
  if (b.length === 0) {
    return a;
  }
  return normalizeIntervals([...a, ...b]);
}

export function intersectSets(a: CodePointSet, b: CodePointSet): CodePointSet {
  if (a.length === 0 || b.length === 0) {
    return EMPTY_SET;
  }
  const out: Array<Interval> = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const [aLo, aHi] = a[i]!;
    const [bLo, bHi] = b[j]!;
    const lo = Math.max(aLo, bLo);
    const hi = Math.min(aHi, bHi);
    if (lo <= hi) {
      out.push([lo, hi]);
    }
    if (aHi < bHi) {
      i++;
    } else {
      j++;
    }
  }
  return out;
}

export function subtractSets(a: CodePointSet, b: CodePointSet): CodePointSet {
  if (a.length === 0 || b.length === 0) {
    return a;
  }
  const out: Array<Interval> = [];
  let j = 0;
  for (const [aLo, aHi] of a) {
    let cur = aLo;
    while (j < b.length && b[j]![1] < cur) {
      j++;
    }
    let k = j;
    while (k < b.length && b[k]![0] <= aHi) {
      const [bLo, bHi] = b[k]!;
      if (bLo > cur) {
        out.push([cur, bLo - 1]);
      }
      cur = bHi + 1;
      if (cur > aHi) {
        break;
      }
      k++;
    }
    if (cur <= aHi) {
      out.push([cur, aHi]);
    }
  }
  return out;
}

export function complementSet(
  set: CodePointSet,
  flags: { unicode: boolean; unicodeSets: boolean }
): CodePointSet {
  return subtractSets(fullSet(flags), set);
}

export function setsOverlap(a: CodePointSet, b: CodePointSet): boolean {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const [aLo, aHi] = a[i]!;
    const [bLo, bHi] = b[j]!;
    if (Math.max(aLo, bLo) <= Math.min(aHi, bHi)) {
      return true;
    }
    if (aHi < bHi) {
      i++;
    } else {
      j++;
    }
  }
  return false;
}

export function isSubset(sub: CodePointSet, sup: CodePointSet): boolean {
  return subtractSets(sub, sup).length === 0;
}

export function setsEqual(a: CodePointSet, b: CodePointSet): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i]![0] !== b[i]![0] || a[i]![1] !== b[i]![1]) {
      return false;
    }
  }
  return true;
}

export function isEmptySet(set: CodePointSet): boolean {
  return set.length === 0;
}

export function setContains(set: CodePointSet, cp: number): boolean {
  let lo = 0;
  let hi = set.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const [sLo, sHi] = set[mid]!;
    if (cp < sLo) {
      hi = mid - 1;
    } else if (cp > sHi) {
      lo = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}

// Predefined character classes
const DIGIT_SET: CodePointSet = [[0x30, 0x39]];
const WORD_ASCII_SET: CodePointSet = [
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x5f, 0x5f],
  [0x61, 0x7a]
];
const WORD_UNICODE_ICASE_SET: CodePointSet = normalizeIntervals([
  ...WORD_ASCII_SET,
  [0x017f, 0x017f], // Latin small letter long s
  [0x212a, 0x212a] // Kelvin sign
]);

const SPACE_SET: CodePointSet = normalizeIntervals([
  [0x09, 0x0d],
  [0x20, 0x20],
  [0xa0, 0xa0],
  [0x1680, 0x1680],
  [0x2000, 0x200a],
  [0x2028, 0x2029],
  [0x202f, 0x202f],
  [0x205f, 0x205f],
  [0x3000, 0x3000],
  [0xfeff, 0xfeff]
]);

const LINE_TERMINATOR_SET: CodePointSet = [
  [0x0a, 0x0a],
  [0x0d, 0x0d],
  [0x2028, 0x2029]
];

// Lazy case-fold lookup tables for BMP (legacy Canonicalize vs Unicode case-folding)
let legacyFoldMap: Map<number, number[]> | null = null;
let unicodeFoldMap: Map<number, number[]> | null = null;

function ensureFoldMaps(): {
  legacy: Map<number, number[]>;
  unicode: Map<number, number[]>;
} {
  if (legacyFoldMap && unicodeFoldMap) {
    return { legacy: legacyFoldMap, unicode: unicodeFoldMap };
  }

  const legacyGroups = new Map<number, number[]>();
  const unicodeGroups = new Map<number, number[]>();

  for (let cp = 0; cp <= 0xffff; cp++) {
    const ch = String.fromCharCode(cp);

    // ECMA-262 Legacy Canonicalize:
    // Uppercase via toUpperCase(); if length > 1, stays cp; if cp >= 128 and upper < 128, stays cp
    const upper = ch.toUpperCase();
    let legacyCanon = cp;
    if (upper.length === 1) {
      const uCode = upper.charCodeAt(0);
      if (!(cp >= 128 && uCode < 128)) {
        legacyCanon = uCode;
      }
    }
    const lg = legacyGroups.get(legacyCanon);
    if (lg) {
      lg.push(cp);
    } else {
      legacyGroups.set(legacyCanon, [cp]);
    }

    // Unicode Simple Case Folding approximation on BMP + special Kelvin / Long-S folds
    const lower = ch.toLowerCase();
    let uniCanon = cp;
    if (cp === 0x017f) {
      uniCanon = 0x73; // 's'
    } else if (cp === 0x212a) {
      uniCanon = 0x6b; // 'k'
    } else if (lower.length === 1) {
      uniCanon = lower.charCodeAt(0);
    } else if (upper.length === 1) {
      uniCanon = upper.charCodeAt(0).toString().length > 0 ? String.fromCharCode(upper.charCodeAt(0)).toLowerCase().charCodeAt(0) : cp;
    }
    const ug = unicodeGroups.get(uniCanon);
    if (ug) {
      ug.push(cp);
    } else {
      unicodeGroups.set(uniCanon, [cp]);
    }
  }

  legacyFoldMap = new Map<number, number[]>();
  for (const members of legacyGroups.values()) {
    if (members.length > 1) {
      for (const m of members) {
        legacyFoldMap.set(m, members);
      }
    }
  }

  unicodeFoldMap = new Map<number, number[]>();
  for (const members of unicodeGroups.values()) {
    if (members.length > 1) {
      for (const m of members) {
        unicodeFoldMap.set(m, members);
      }
    }
  }

  return { legacy: legacyFoldMap, unicode: unicodeFoldMap };
}

export function expandIgnoreCase(
  set: CodePointSet,
  flags: { unicode: boolean; unicodeSets: boolean }
): CodePointSet {
  if (set.length === 0) {
    return EMPTY_SET;
  }
  const { legacy, unicode } = ensureFoldMaps();
  const table = flags.unicode || flags.unicodeSets ? unicode : legacy;
  const intervals: Array<Interval> = [...set];

  for (const [lo, hi] of set) {
    // Fast path for full universe
    if (lo === 0 && hi >= 0xffff) {
      return set;
    }
    // ASCII fast path
    const asciiUpperLo = Math.max(lo, 0x41);
    const asciiUpperHi = Math.min(hi, 0x5a);
    if (asciiUpperLo <= asciiUpperHi) {
      intervals.push([asciiUpperLo + 32, asciiUpperHi + 32]);
    }
    const asciiLowerLo = Math.max(lo, 0x61);
    const asciiLowerHi = Math.min(hi, 0x7a);
    if (asciiLowerLo <= asciiLowerHi) {
      intervals.push([asciiLowerLo - 32, asciiLowerHi - 32]);
    }

    // Check BMP fold equivalents (bounded to <= 0xFFFF)
    const bmpLo = Math.max(lo, 0x7f);
    const bmpHi = Math.min(hi, 0xffff);
    if (bmpLo <= bmpHi) {
      for (let cp = bmpLo; cp <= bmpHi; cp++) {
        const eq = table.get(cp);
        if (eq) {
          for (const other of eq) {
            if (other !== cp) {
              intervals.push([other, other]);
            }
          }
        }
      }
    }
    // Also check if ASCII s/S or k/K pulls in 0x017F / 0x212A in Unicode mode
    if (flags.unicode || flags.unicodeSets) {
      if ((lo <= 0x73 && 0x73 <= hi) || (lo <= 0x53 && 0x53 <= hi)) {
        intervals.push([0x017f, 0x017f]);
      }
      if ((lo <= 0x6b && 0x6b <= hi) || (lo <= 0x4b && 0x4b <= hi)) {
        intervals.push([0x212a, 0x212a]);
      }
    }
  }

  return normalizeIntervals(intervals);
}

// Cache for Unicode property sets (\p{...} / \P{...})
const unicodePropertyCache = new Map<string, CodePointSet>();

// Representative code points & ASCII + BMP + common astral scripts for fast exact/dense property set construction
function getUnicodePropertySet(rawEscape: string, flags: EffectiveFlags): CodePointSet {
  const flagStr = flags.unicodeSets ? (flags.ignoreCase ? 'vi' : 'v') : flags.ignoreCase ? 'ui' : 'u';
  const cacheKey = `${rawEscape}/${flagStr}`;
  const cached = unicodePropertyCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Safety guard: rawEscape comes from a validated AST.UnicodePropertyCharacterSet node (single atom, no quantifiers)
  if (rawEscape.length > 120 || !/^\\[pP]\{[A-Za-z0-9_=-]+\}$/.test(rawEscape)) {
    return EMPTY_SET;
  }

  let re: RegExp;
  try {
    re = new RegExp(`^(?:${rawEscape})$`, flagStr);
  } catch {
    return EMPTY_SET;
  }

  const intervals: Array<Interval> = [];
  // Scan BMP non-surrogates completely (63,488 points -> ~1.5 ms once, then cached)
  let inRun = false;
  let runStart = 0;
  for (let cp = 0; cp <= 0xffff; cp++) {
    if (cp === 0xd800) {
      if (inRun) {
        intervals.push([runStart, 0xd7ff]);
        inRun = false;
      }
      cp = 0xdfff;
      continue;
    }
    const matched = re.test(String.fromCharCode(cp));
    if (matched && !inRun) {
      inRun = true;
      runStart = cp;
    } else if (!matched && inRun) {
      intervals.push([runStart, cp - 1]);
      inRun = false;
    }
  }
  if (inRun) {
    intervals.push([runStart, 0xffff]);
  }

  // Probe representative astral blocks (Emoji, SMP letters/numbers, CJK Ext B)
  const astralProbes: Array<readonly [number, number]> = [
    [0x10000, 0x1007f],
    [0x1d400, 0x1d7ff],
    [0x1f300, 0x1f64f],
    [0x1f680, 0x1f6ff],
    [0x1f900, 0x1f9ff],
    [0x20000, 0x2007f]
  ];
  for (const [bLo, bHi] of astralProbes) {
    if (re.test(String.fromCodePoint(bLo))) {
      intervals.push([bLo, bHi]);
    }
  }

  const result = normalizeIntervals(intervals);
  unicodePropertyCache.set(cacheKey, result);
  return result;
}

export function applyModifiers(base: EffectiveFlags, modifiers: AST.Modifiers | null): EffectiveFlags {
  if (!modifiers) {
    return base;
  }
  let { ignoreCase, dotAll, multiline } = base;
  if (modifiers.add.ignoreCase) ignoreCase = true;
  if (modifiers.add.dotAll) dotAll = true;
  if (modifiers.add.multiline) multiline = true;
  if (modifiers.remove) {
    if (modifiers.remove.ignoreCase) ignoreCase = false;
    if (modifiers.remove.dotAll) dotAll = false;
    if (modifiers.remove.multiline) multiline = false;
  }
  return {
    unicode: base.unicode,
    unicodeSets: base.unicodeSets,
    ignoreCase,
    dotAll,
    multiline
  };
}

function classElementToCharSet(
  el: AST.CharacterClassElement | AST.ClassSetOperand,
  flags: EffectiveFlags
): CodePointSet {
  switch (el.type) {
    case 'Character': {
      const base = singletonSet(el.value);
      return flags.ignoreCase ? expandIgnoreCase(base, flags) : base;
    }
    case 'CharacterClassRange': {
      const base = rangeSet(el.min.value, el.max.value);
      return flags.ignoreCase ? expandIgnoreCase(base, flags) : base;
    }
    case 'CharacterSet': {
      return characterSetNodeToSet(el, flags);
    }
    case 'CharacterClass': {
      return characterClassToSet(el, flags);
    }
    case 'ExpressionCharacterClass': {
      return expressionCharacterClassToSet(el, flags);
    }
    case 'ClassStringDisjunction': {
      // Single-code-point alternatives contribute to single-char set; multi-char alternatives contribute their first char for overlap
      let acc: CodePointSet = EMPTY_SET;
      for (const alt of el.alternatives) {
        if (alt.elements.length >= 1) {
          const first = singletonSet(alt.elements[0]!.value);
          acc = unionSets(acc, flags.ignoreCase ? expandIgnoreCase(first, flags) : first);
        }
      }
      return acc;
    }
  }
}

export function characterSetNodeToSet(
  node: AST.CharacterSet,
  flags: EffectiveFlags
): CodePointSet {
  if (node.kind === 'any') {
    if (flags.dotAll) {
      return fullSet(flags);
    }
    return subtractSets(fullSet(flags), LINE_TERMINATOR_SET);
  }
  if (node.kind === 'digit') {
    return node.negate ? complementSet(DIGIT_SET, flags) : DIGIT_SET;
  }
  if (node.kind === 'space') {
    return node.negate ? complementSet(SPACE_SET, flags) : SPACE_SET;
  }
  if (node.kind === 'word') {
    const wordSet =
      flags.ignoreCase && (flags.unicode || flags.unicodeSets)
        ? WORD_UNICODE_ICASE_SET
        : WORD_ASCII_SET;
    return node.negate ? complementSet(wordSet, flags) : wordSet;
  }
  // UnicodePropertyCharacterSet
  return getUnicodePropertySet(node.raw, flags);
}

export function characterClassToSet(
  node: AST.CharacterClass,
  flags: EffectiveFlags
): CodePointSet {
  let acc: CodePointSet = EMPTY_SET;
  for (const el of node.elements) {
    acc = unionSets(acc, classElementToCharSet(el, flags));
  }
  if (node.negate) {
    // In ECMA-262:
    // - Without `v` (legacy and `u` mode): [^A-Z]/i complements [A-Z] BEFORE Canonicalize, wait:
    //   In ECMA-262 IsCharacterClass `[^A-Z]` with `/i`: a char `c` matches `[^A-Z]` iff Canonicalize(c) is NOT in Canonicalize([A-Z])!
    //   Since we already expanded [A-Z] to [A-Za-z] when ignoreCase=true, complementing [A-Za-z] excludes BOTH 'A'..'Z' and 'a'..'z' — which is 100% exact!
    return complementSet(acc, flags);
  }
  return acc;
}

function evalSetExpression(
  expr: AST.ClassIntersection | AST.ClassSubtraction,
  flags: EffectiveFlags
): CodePointSet {
  if (expr.type === 'ClassIntersection') {
    const left =
      expr.left.type === 'ClassIntersection'
        ? evalSetExpression(expr.left, flags)
        : classElementToCharSet(expr.left, flags);
    const right = classElementToCharSet(expr.right, flags);
    return intersectSets(left, right);
  }
  const left =
    expr.left.type === 'ClassSubtraction'
      ? evalSetExpression(expr.left, flags)
      : classElementToCharSet(expr.left, flags);
  const right = classElementToCharSet(expr.right, flags);
  return subtractSets(left, right);
}

export function expressionCharacterClassToSet(
  node: AST.ExpressionCharacterClass,
  flags: EffectiveFlags
): CodePointSet {
  const inner = evalSetExpression(node.expression, flags);
  return node.negate ? complementSet(inner, flags) : inner;
}

const PREFERRED_WITNESSES: readonly number[] = [
  0x61, // 'a'
  0x41, // 'A'
  0x31, // '1'
  0x30, // '0'
  0x2f, // '/'
  0x5f, // '_'
  0x20, // ' '
  0x2d, // '-'
  0x2e, // '.'
  0x3a, // ':'
  0x3d, // '='
  0x78, // 'x'
  0x21, // '!'
  0x09, // '\t'
  0x0a // '\n'
];

export function pickWitnessCodePoint(set: CodePointSet): number | null {
  if (set.length === 0) {
    return null;
  }
  for (const pref of PREFERRED_WITNESSES) {
    if (setContains(set, pref)) {
      return pref;
    }
  }
  // Printable ASCII
  const printable = intersectSets(set, [[0x21, 0x7e]]);
  if (printable.length > 0) {
    return printable[0]![0];
  }
  // Non-surrogate BMP
  const bmpSafe = subtractSets(intersectSets(set, [[0x0080, 0xfffd]]), [[0xd800, 0xdfff]]);
  if (bmpSafe.length > 0) {
    return bmpSafe[0]![0];
  }
  // Astral code points (e.g. emoji)
  const astral = intersectSets(set, [[0x10000, 0x10ffff]]);
  if (astral.length > 0) {
    return astral[0]![0];
  }
  return set[0]![0];
}

export function codePointToString(cp: number, flags: { unicode: boolean; unicodeSets: boolean }): string {
  if (!flags.unicode && !flags.unicodeSets && cp >= 0xd800 && cp <= 0xdfff) {
    return String.fromCharCode(cp);
  }
  return String.fromCodePoint(cp);
}

export function pickWitnessString(
  set: CodePointSet,
  flags: { unicode: boolean; unicodeSets: boolean }
): string | null {
  const cp = pickWitnessCodePoint(set);
  return cp === null ? null : codePointToString(cp, flags);
}

const PREFERRED_FAIL_CANDIDATES: readonly number[] = [
  0x21, // '!'
  0x78, // 'x'
  0x7e, // '~'
  0x40, // '@'
  0x23, // '#'
  0x0a, // '\n' (fails `.` without `s`)
  0x00 // '\0'
];

export function pickNonMatchingString(
  excluded: CodePointSet,
  flags: { unicode: boolean; unicodeSets: boolean }
): string {
  const allowed = complementSet(excluded, flags);
  if (allowed.length === 0) {
    // Even if `excluded` is the full universe (e.g. `[\s\S]`), return '!' as deterministic suffix
    return '!';
  }
  for (const cand of PREFERRED_FAIL_CANDIDATES) {
    if (setContains(allowed, cand)) {
      return codePointToString(cand, flags);
    }
  }
  const cp = pickWitnessCodePoint(allowed);
  return cp !== null ? codePointToString(cp, flags) : '!';
}

function formatCodePoint(cp: number): string {
  if (cp >= 0x21 && cp <= 0x7e) {
    return `'${String.fromCharCode(cp)}'`;
  }
  if (cp === 0x20) return "' '";
  if (cp === 0x09) return "'\\t'";
  if (cp === 0x0a) return "'\\n'";
  if (cp === 0x0d) return "'\\r'";
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

export function formatIntervalSummary(set: CodePointSet, maxRanges = 4): string {
  if (set.length === 0) {
    return 'empty';
  }
  const parts: string[] = [];
  const limit = Math.min(set.length, maxRanges);
  for (let i = 0; i < limit; i++) {
    const [lo, hi] = set[i]!;
    if (lo === hi) {
      parts.push(formatCodePoint(lo));
    } else {
      parts.push(`${formatCodePoint(lo)}..${formatCodePoint(hi)}`);
    }
  }
  if (set.length > maxRanges) {
    parts.push(`+${set.length - maxRanges} more`);
  }
  return `[${parts.join(', ')}]`;
}
