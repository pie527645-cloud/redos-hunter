import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { analyzePattern } from '../src/index.js';

describe('Static ReDoS rules (RDH001, RDH002, RDH003, RDH005, RDH006)', () => {
  it('flags RDH001 on nested quantifiers with cross-iteration overlap', () => {
    const f1 = analyzePattern('(a+)+$');
    assert.equal(f1.length, 1);
    assert.equal(f1[0]?.ruleId, 'RDH001');
    assert.equal(f1[0]?.severity, 'high');
    assert.equal(f1[0]?.complexity, 'exp');
    assert.equal(f1[0]?.attack?.pump, 'a');

    const f2 = analyzePattern('(\\w+\\s?)*$');
    assert.equal(f2.length, 1);
    assert.equal(f2[0]?.ruleId, 'RDH001');
    assert.equal(f2[0]?.complexity, 'exp');
  });

  it('flags RDH002 on overlapping alternation under a quantifier', () => {
    for (const pat of ['(a|a)*$', '(\\w|\\d)+$', '(.|\\s)*$']) {
      const res = analyzePattern(pat);
      assert.ok(
        res.some((f) => f.ruleId === 'RDH002' && f.severity === 'high' && f.complexity === 'exp'),
        `Expected RDH002 on ${pat}`
      );
    }
  });

  it('flags RDH003 on adjacent overlapping quantifiers', () => {
    for (const pat of ['^\\d+\\d+$', '\\s*\\w*\\s*$', '.*.*=']) {
      const res = analyzePattern(pat);
      assert.ok(
        res.some((f) => f.ruleId === 'RDH003' && f.complexity === 'poly'),
        `Expected RDH003 on ${pat}`
      );
    }
    const wildcard = analyzePattern('.*.*=');
    assert.equal(wildcard[0]?.severity, 'high');
    assert.equal(wildcard[0]?.attack?.suffix, '!');
  });

  it('flags RDH005 on nested delimiter loops and unanchored trailing quantifiers', () => {
    const nestedSlash = analyzePattern('^(\\w+\\/?)+$');
    assert.equal(nestedSlash.length, 1);
    assert.equal(nestedSlash[0]?.ruleId, 'RDH005');
    assert.equal(nestedSlash[0]?.complexity, 'exp');

    const unanchoredLoop = analyzePattern('(a\\/*)+b');
    assert.equal(unanchoredLoop.length, 1);
    assert.equal(unanchoredLoop[0]?.ruleId, 'RDH005');
    assert.equal(unanchoredLoop[0]?.complexity, 'poly');

    const trimSlashes = analyzePattern('^\\/+|\\/+$/'.slice(0, -1), 'g');
    assert.equal(trimSlashes.length, 1);
    assert.equal(trimSlashes[0]?.ruleId, 'RDH005');
    assert.equal(trimSlashes[0]?.complexity, 'poly');

    const trailingSpace = analyzePattern('\\s+$');
    assert.equal(trailingSpace.length, 1);
    assert.equal(trailingSpace[0]?.ruleId, 'RDH005');
  });

  it('flags RDH006 on backreferences inside quantified groups while keeping atomic lookahead emulation clean', () => {
    const unsafeBackref = analyzePattern('^(([a-z])\\2)+$');
    assert.ok(unsafeBackref.some((f) => f.ruleId === 'RDH006' && f.severity === 'medium'));

    const quantifiedRef = analyzePattern('^(a+)\\1+$');
    assert.ok(quantifiedRef.some((f) => f.ruleId === 'RDH006'));

    // JS atomic group emulation `(?=(a+))\1` must produce 0 findings
    const atomicSafe = analyzePattern('^(?:(?=(\\w+))\\1\\/?)+$');
    assert.equal(atomicSafe.length, 0);
  });

  it('emits 0 findings on anchored-safe and disjoint linear patterns', () => {
    const safePatterns: Array<[string, string]> = [
      ['^[a-zA-Z0-9_-]+$', ''],
      ['^\\w+(?:\\/\\w+)*\\/?$', ''],
      ['^(?:\\\\.|[^"\\\\])*$', ''],
      ['^([a-z]\\d?)+$', ''],
      ['^\\/+$', ''],
      ['^\\s*\\S+\\s*$', ''],
      ['^[^=\\r\\n]*=$', ''],
      ['^(?:\\w+(?:\\s|$))*$', '']
    ];

    for (const [pat, flags] of safePatterns) {
      const res = analyzePattern(pat, flags);
      assert.deepEqual(res, [], `Expected 0 findings on safe pattern /${pat}/${flags}`);
    }
  });
});
