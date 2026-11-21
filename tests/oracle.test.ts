import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { runWorkspaceCheck } from '../src/index.js';

const THIS_DIR = path.dirname(fileURLToPath(import.meta.url));
// Resolve committed source fixture from repo root regardless of dist-test output depth
const FIXTURE_PATH = path.resolve(THIS_DIR, '../../tests/fixtures/repo-atlas-prefix-oracle.ts');

describe('Committed pre-fix repo-atlas ReDoS regression oracle', () => {
  it('flags all four committed pre-fix patterns (both trimSlashes /^\\/+|\\/+$/g, ^(\\w+\\/?)+$, and (a+)+$) and confirms empirically', async () => {
    const report = await runWorkspaceCheck({
      paths: [FIXTURE_PATH],
      confirm: true,
      timeoutMs: 250
    });

    assert.equal(report.scannedFilesCount, 1);
    assert.equal(report.extractedPatternsCount, 4);
    assert.equal(report.findings.length, 4);

    const rdh005 = report.findings.filter((f) => f.ruleId === 'RDH005');
    const rdh001 = report.findings.filter((f) => f.ruleId === 'RDH001');

    assert.equal(rdh005.length, 3, 'Expected 3 RDH005 findings (2 trimSlashes + 1 ^(\\w+\\/?)+$)');
    assert.equal(rdh001.length, 1, 'Expected 1 RDH001 finding ((a+)+$)');

    for (const f of report.findings) {
      assert.equal(f.severity, 'high');
      assert.equal(
        f.evidence?.status,
        'confirmed',
        `Expected empirical confirmation for /${f.pattern}/${f.flags}`
      );
    }
  });
});
