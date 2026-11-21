import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  analyzePattern,
  confirmFindingInSandbox,
  evaluatePatternInSandbox,
  EXP_PUMP_COUNTS,
  formatCheckReport,
  formatSarifReport,
  POLY_PUMP_COUNTS,
  SandboxExecutor,
  type CheckReport
} from '../src/index.js';

describe('Isolated sandbox empirical confirmation and Windows timeout termination', () => {
  it('terminates catastrophic (a+)+$ on "a".repeat(40) + "!" within timeoutMs + 100 ms on worker backend', async () => {
    const timeoutMs = 250;
    const executor = new SandboxExecutor('worker');
    try {
      await executor.warmup();
      const t0 = performance.now();
      const res = await executor.runProbe(
        {
          source: '(a+)+$',
          flags: '',
          input: 'a'.repeat(40) + '!'
        },
        timeoutMs
      );
      const elapsed = performance.now() - t0;

      assert.equal(res.timedOut, true);
      assert.equal(res.backend, 'worker');
      assert.ok(
        elapsed <= timeoutMs + 100,
        `Worker termination exceeded budget: ${elapsed.toFixed(1)} ms > ${timeoutMs + 100} ms`
      );
    } finally {
      await executor.close();
    }
  });

  it('also terminates catastrophic (a+)+$ on "a".repeat(40) + "!" within timeoutMs + 100 ms on child_process backend', async () => {
    const timeoutMs = 250;
    const executor = new SandboxExecutor('child');
    try {
      await executor.warmup();
      const t0 = performance.now();
      const res = await executor.runProbe(
        {
          source: '(a+)+$',
          flags: '',
          input: 'a'.repeat(40) + '!'
        },
        timeoutMs
      );
      const elapsed = performance.now() - t0;

      assert.equal(res.timedOut, true);
      assert.equal(res.backend, 'child');
      assert.ok(
        elapsed <= timeoutMs + 100,
        `Child kill exceeded budget: ${elapsed.toFixed(1)} ms > ${timeoutMs + 100} ms`
      );
    } finally {
      await executor.close();
    }
  });

  it('terminates cold one-shot evaluatePatternInSandbox within timeoutMs + 100 ms', async () => {
    const timeoutMs = 250;
    const t0 = performance.now();
    const res = await evaluatePatternInSandbox(
      {
        source: '(a+)+$',
        flags: '',
        input: 'a'.repeat(40) + '!'
      },
      { timeoutMs }
    );
    const elapsed = performance.now() - t0;
    assert.equal(res.timedOut, true);
    assert.ok(
      elapsed <= timeoutMs + 100,
      `Cold sandbox termination took ${elapsed.toFixed(1)} ms > ${timeoutMs + 100} ms`
    );
  });

  it('confirms exponential and polynomial findings using deterministic pump schedules and never leaks timing to SARIF', async () => {
    const expFindings = analyzePattern('(a+)+$', '', { file: 'exp.ts', line: 1, column: 1 });
    const polyFindings = analyzePattern('^\\/+|\\/+$/'.slice(0, -1), 'g', {
      file: 'poly.ts',
      line: 2,
      column: 1
    });

    const expFinding = expFindings[0]!;
    const polyFinding = polyFindings[0]!;
    const fpBefore = expFinding.fingerprint;

    const executor = new SandboxExecutor('auto');
    try {
      expFinding.evidence = await confirmFindingInSandbox(expFinding, executor, 200);
      polyFinding.evidence = await confirmFindingInSandbox(polyFinding, executor, 250);
    } finally {
      await executor.close();
    }

    assert.equal(expFinding.evidence.status, 'confirmed');
    assert.equal(expFinding.evidence.measuredClass, 'exp');
    assert.equal(expFinding.evidence.samples[0]?.n, EXP_PUMP_COUNTS[0]);
    assert.equal(expFinding.fingerprint, fpBefore);
    assert.equal(expFinding.severity, 'high');

    assert.equal(polyFinding.evidence.status, 'confirmed');
    assert.equal(polyFinding.evidence.measuredClass, 'poly');
    assert.equal(polyFinding.evidence.samples[0]?.n, POLY_PUMP_COUNTS[0]);

    const report: CheckReport = {
      scannedFilesCount: 2,
      extractedPatternsCount: 2,
      suppressedCount: 0,
      findings: [expFinding, polyFinding]
    };

    const jsonText = formatCheckReport(report, 'json');
    assert.ok(jsonText.includes('"durationMs"'));
    assert.ok(jsonText.includes('"evidence"'));

    const sarifText = formatSarifReport(report);
    assert.equal(sarifText.includes('durationMs'), false);
    assert.equal(sarifText.includes('evidence'), false);
    assert.equal(sarifText.includes('growthRatio'), false);
  });
});
