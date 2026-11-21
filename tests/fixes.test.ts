import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { analyzePattern, CANONICAL_REWRITE_CATALOG } from '../src/index.js';

describe('Mandatory Fix-Hint Self-Check (all suggested rewrites pass RDH001-006)', () => {
  it('emits 0 findings on every rewrite in CANONICAL_REWRITE_CATALOG', () => {
    assert.ok(CANONICAL_REWRITE_CATALOG.length >= 10);

    for (const entry of CANONICAL_REWRITE_CATALOG) {
      const before = analyzePattern(entry.vulnerablePattern, entry.vulnerableFlags);
      assert.ok(
        before.some((f) => f.ruleId === entry.ruleId),
        `Expected ${entry.ruleId} on vulnerable pattern /${entry.vulnerablePattern}/${entry.vulnerableFlags}`
      );

      const after = analyzePattern(entry.safeRewrite, entry.safeFlags);
      assert.deepEqual(
        after,
        [],
        `Mandatory self-check failed: canonical rewrite /${entry.safeRewrite}/${entry.safeFlags} triggered ${JSON.stringify(after)}`
      );
    }
  });

  it('dynamically generates concrete rewrites across vulnerable patterns and verifies 0 static findings on every emitted rewrite', () => {
    const vulnerableCorpus: Array<[string, string]> = [
      ['(a+)+$', ''],
      ['([a-z]+)*$', 'i'],
      ['(\\w+\\s?)*$', ''],
      ['(\\w+\\s?)+$', ''],
      ['^(a|a)*$', ''],
      ['^(\\w|\\d)+$', ''],
      ['^(.|\\s)*$', ''],
      ['^([a-z]|[d-m])+$', ''],
      ['^\\d+\\d+$', ''],
      ['.*.*=', ''],
      ['.*.*:', 's'],
      ['^(\\w+\\/?)+$', ''],
      ['(a\\/*)+b', ''],
      ['^\\/+|\\/+$', 'g'],
      ['\\s+$', '']
    ];

    let generatedRewriteCount = 0;

    for (const [pat, flags] of vulnerableCorpus) {
      const findings = analyzePattern(pat, flags);
      assert.ok(findings.length >= 1, `Expected finding on /${pat}/${flags}`);

      for (const f of findings) {
        if (f.fix && f.fix.rewrite !== null) {
          generatedRewriteCount++;
          const rewriteFlags = f.fix.rewriteFlags ?? flags;
          const recheck = analyzePattern(f.fix.rewrite, rewriteFlags);
          assert.deepEqual(
            recheck,
            [],
            `Generated rewrite /${f.fix.rewrite}/${rewriteFlags} (for /${pat}/${flags}, ${f.ruleId}) failed self-check: ${JSON.stringify(recheck)}`
          );
        }
      }
    }

    assert.ok(
      generatedRewriteCount >= vulnerableCorpus.length,
      `Expected every corpus pattern to produce a concrete rewrite, got ${generatedRewriteCount}`
    );
  });
});
