import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  analyzePattern,
  complementSet,
  expandIgnoreCase,
  intersectSets,
  rangeSet,
  setsEqual,
  setsOverlap,
  subtractSets,
  unionSets
} from '../src/index.js';

describe('CodePointSet interval algebra and flag-aware overlap math', () => {
  it('computes union, intersection, subtraction, and complement accurately', () => {
    const lower = rangeSet(0x61, 0x7a); // a-z
    const mid = rangeSet(0x6d, 0x70); // m-p
    const diff = subtractSets(lower, mid);

    assert.equal(setsOverlap(diff, mid), false);
    assert.equal(setsEqual(unionSets(diff, mid), lower), true);
    assert.deepEqual(intersectSets(lower, rangeSet(0x70, 0x7a)), [[0x70, 0x7a]]);

    const comp = complementSet(lower, { unicode: false, unicodeSets: false });
    assert.equal(setsOverlap(comp, lower), false);
  });

  it('honors i-flag case-folding between [A-Z] and [a-z]', () => {
    // Without `i`: [A-Z] and [a-z] are disjoint -> 0 findings
    const caseSensitive = analyzePattern('^([A-Z]|[a-z])+$', '');
    assert.equal(caseSensitive.length, 0);

    // With `i`: [A-Z] folds onto [a-z] -> RDH002 high
    const caseInsensitive = analyzePattern('^([A-Z]|[a-z])+$', 'i');
    assert.equal(caseInsensitive.length, 1);
    assert.equal(caseInsensitive[0]?.ruleId, 'RDH002');
    assert.equal(caseInsensitive[0]?.severity, 'high');

    // Legacy vs Unicode `i` folding for U+017F (Latin small letter long s)
    const legacyLongS = expandIgnoreCase([[0x017f, 0x017f]], {
      unicode: false,
      unicodeSets: false
    });
    assert.equal(setsOverlap(legacyLongS, [[0x73, 0x73]]), false);

    const unicodeLongS = expandIgnoreCase([[0x017f, 0x017f]], {
      unicode: true,
      unicodeSets: false
    });
    assert.equal(setsOverlap(unicodeLongS, [[0x73, 0x73]]), true);
  });

  it('supports v-flag (unicodeSets) character class subtraction and intersection', () => {
    // Disjoint via v-flag subtraction: [[a-z]--[m-p]] vs [m-p] -> 0 findings
    const safeSubtracted = analyzePattern('^([[a-z]--[m-p]]|[m-p])+$', 'v');
    assert.equal(safeSubtracted.length, 0);

    // Overlapping v-flag intersection: [\w&&[a-f]] vs [d-z] overlaps on d..f -> RDH002
    const overlappingIntersect = analyzePattern('^([\\w&&[a-f]]|[d-z])+$', 'v');
    assert.equal(overlappingIntersect.length, 1);
    assert.equal(overlappingIntersect[0]?.ruleId, 'RDH002');
  });

  it('distinguishes emoji surrogate pairs with and without u flag', () => {
    // U+1F600 (😀 = \uD83D\uDE00) vs U+1F602 (😂 = \uD83D\uDE02)
    // Without `u`, [😀] is {\uD83D, \uDE00} and [😂] is {\uD83D, \uDE02}, colliding on high surrogate 0xD83D!
    const withoutU = analyzePattern('^([\u{1F600}]|[\u{1F602}])+$', '');
    assert.equal(withoutU.length, 1);
    assert.equal(withoutU[0]?.ruleId, 'RDH002');

    // With `u`, [😀] is {0x1F600} and [😂] is {0x1F602} -> completely disjoint!
    const withU = analyzePattern('^([\u{1F600}]|[\u{1F602}])+$', 'u');
    assert.equal(withU.length, 0);

    // Nested quantifier on astral emoji with `u` -> RDH001 withastral witness
    const nestedEmoji = analyzePattern('^(\u{1F600}+)+$', 'u');
    assert.equal(nestedEmoji.length, 1);
    assert.equal(nestedEmoji[0]?.ruleId, 'RDH001');
    assert.equal(nestedEmoji[0]?.attack?.pump, '\u{1F600}');
  });
});
