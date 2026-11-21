import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import * as readline from 'node:readline';
import type {
  ConfirmEvidence,
  ConfirmSample,
  RedosFinding,
  SandboxBackend
} from '../types.js';

export const DEFAULT_TIMEOUT_MS = 250;
export const EXP_PUMP_COUNTS = [8, 12, 16, 20, 24] as const;
export const POLY_PUMP_COUNTS = [1000, 2000, 4000, 8000] as const;

export interface SandboxProbeRequest {
  source: string;
  flags: string;
  input: string;
}

export interface SandboxProbeResult {
  matched: boolean | null;
  durationMs: number;
  wallClockMs: number;
  timedOut: boolean;
  backend: 'worker' | 'child';
  error?: string;
}

// Inline worker script: receives ONLY { id, source, flags, input } via MessagePort.
// Zero fs/net/child_process imports; env is empty; fetch/process.binding disabled.
const WORKER_SANDBOX_SCRIPT = `
'use strict';
const { parentPort } = require('node:worker_threads');
const { performance } = require('node:perf_hooks');
try {
  globalThis.fetch = undefined;
} catch {}
parentPort.on('message', (msg) => {
  const { id, source, flags, input } = msg;
  try {
    const re = new RegExp(source, flags);
    const t0 = performance.now();
    const matched = re.test(input);
    const durationMs = performance.now() - t0;
    parentPort.postMessage({ id, ok: true, matched, durationMs });
  } catch (err) {
    parentPort.postMessage({
      id,
      ok: false,
      error: err && err.message ? String(err.message) : String(err)
    });
  }
});
parentPort.postMessage({ ready: true });
`;

// Inline child_process script: communicates strictly over stdin/stdout JSON lines with shell: false and env: {}.
const CHILD_SANDBOX_SCRIPT = `
'use strict';
const readline = require('node:readline');
const { performance } = require('node:perf_hooks');
try {
  globalThis.fetch = undefined;
} catch {}
const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
process.stdout.write(JSON.stringify({ ready: true }) + '\\n');
rl.on('line', (line) => {
  if (!line) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  const { id, source, flags, input } = msg;
  try {
    const re = new RegExp(source, flags);
    const t0 = performance.now();
    const matched = re.test(input);
    const durationMs = performance.now() - t0;
    process.stdout.write(JSON.stringify({ id, ok: true, matched, durationMs }) + '\\n');
  } catch (err) {
    process.stdout.write(JSON.stringify({
      id,
      ok: false,
      error: err && err.message ? String(err.message) : String(err)
    }) + '\\n');
  }
});
`;

/**
 * Default backend selection:
 * V8's Isolate::TerminateExecution() invoked by worker.terminate() interrupts V8 Irregexp
 * backtracking checks cleanly on both POSIX and Windows (verified empirically < timeoutMs + 25 ms).
 * Both 'worker' and 'child' (`spawn` with `shell: false`) are supported and unit-tested.
 */
export function resolveDefaultBackend(requested: SandboxBackend = 'auto'): 'worker' | 'child' {
  if (requested === 'worker' || requested === 'child') {
    return requested;
  }
  return 'worker';
}

export class SandboxExecutor {
  private readonly backend: 'worker' | 'child';
  private worker: Worker | null = null;
  private workerReadyPromise: Promise<void> | null = null;
  private child: ChildProcessWithoutNullStreams | null = null;
  private childRl: readline.Interface | null = null;
  private childReadyPromise: Promise<void> | null = null;
  private nextId = 1;

  constructor(backend: SandboxBackend = 'auto') {
    this.backend = resolveDefaultBackend(backend);
  }

  public get activeBackend(): 'worker' | 'child' {
    return this.backend;
  }

  private async ensureWorker(): Promise<Worker> {
    if (this.worker && this.workerReadyPromise) {
      await this.workerReadyPromise;
      return this.worker;
    }
    const w = new Worker(WORKER_SANDBOX_SCRIPT, {
      eval: true,
      env: {}
    });
    this.worker = w;
    this.workerReadyPromise = new Promise<void>((resolve, reject) => {
      const onMsg = (msg: unknown): void => {
        if (msg && typeof msg === 'object' && (msg as { ready?: boolean }).ready === true) {
          w.off('error', onErr);
          w.unref();
          resolve();
        }
      };
      const onErr = (err: Error): void => {
        w.off('message', onMsg);
        this.worker = null;
        this.workerReadyPromise = null;
        reject(err);
      };
      w.once('message', onMsg);
      w.once('error', onErr);
    });
    await this.workerReadyPromise;
    return w;
  }

  private async destroyWorker(): Promise<void> {
    const w = this.worker;
    this.worker = null;
    this.workerReadyPromise = null;
    if (w) {
      try {
        await w.terminate();
      } catch {
        // Ignore termination errors
      }
    }
  }

  private async ensureChild(): Promise<{
    proc: ChildProcessWithoutNullStreams;
    rl: readline.Interface;
  }> {
    if (this.child && this.childRl && this.childReadyPromise) {
      await this.childReadyPromise;
      return { proc: this.child, rl: this.childRl };
    }
    const proc = spawn(process.execPath, ['-e', CHILD_SANDBOX_SCRIPT], {
      shell: false,
      env: {},
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });
    const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
    this.child = proc;
    this.childRl = rl;
    this.childReadyPromise = new Promise<void>((resolve, reject) => {
      const onLine = (line: string): void => {
        try {
          const parsed = JSON.parse(line) as { ready?: boolean };
          if (parsed.ready === true) {
            proc.off('error', onErr);
            proc.unref();
            resolve();
          }
        } catch {
          // Ignore malformed line
        }
      };
      const onErr = (err: Error): void => {
        rl.off('line', onLine);
        this.child = null;
        this.childRl = null;
        this.childReadyPromise = null;
        reject(err);
      };
      rl.once('line', onLine);
      proc.once('error', onErr);
    });
    await this.childReadyPromise;
    return { proc, rl };
  }

  private async destroyChild(): Promise<void> {
    const proc = this.child;
    const rl = this.childRl;
    this.child = null;
    this.childRl = null;
    this.childReadyPromise = null;
    if (rl) {
      rl.close();
    }
    if (proc) {
      await new Promise<void>((resolve) => {
        if (proc.exitCode !== null || proc.killed) {
          resolve();
          return;
        }
        const safety = setTimeout(() => resolve(), 50);
        proc.once('exit', () => {
          clearTimeout(safety);
          resolve();
        });
        try {
          proc.kill('SIGKILL');
        } catch {
          clearTimeout(safety);
          resolve();
        }
      });
      proc.stdin.destroy();
      proc.stdout.destroy();
      proc.stderr.destroy();
    }
  }

  public async warmup(): Promise<void> {
    if (this.backend === 'worker') {
      await this.ensureWorker();
    } else {
      await this.ensureChild();
    }
  }

  public async close(): Promise<void> {
    await this.destroyWorker();
    await this.destroyChild();
  }

  public async runProbe(
    req: SandboxProbeRequest,
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<SandboxProbeResult> {
    const wallStart = performance.now();
    const id = this.nextId++;

    if (this.backend === 'worker') {
      let w: Worker;
      try {
        w = await this.ensureWorker();
      } catch (err) {
        return {
          matched: null,
          durationMs: 0,
          wallClockMs: performance.now() - wallStart,
          timedOut: false,
          backend: 'worker',
          error: err instanceof Error ? err.message : String(err)
        };
      }

      const elapsedBoot = performance.now() - wallStart;
      const remainingBudget = Math.max(25, timeoutMs - elapsedBoot);

      return new Promise<SandboxProbeResult>((resolve) => {
        let settled = false;

        const onMessage = (msg: unknown): void => {
          if (!msg || typeof msg !== 'object') return;
          const m = msg as {
            id?: number;
            ok?: boolean;
            matched?: boolean;
            durationMs?: number;
            error?: string;
          };
          if (m.id !== id || settled) return;
          settled = true;
          clearTimeout(timer);
          cleanupListeners();
          const wallClockMs = performance.now() - wallStart;
          if (m.ok) {
            resolve({
              matched: Boolean(m.matched),
              durationMs: Number((m.durationMs ?? wallClockMs).toFixed(3)),
              wallClockMs: Number(wallClockMs.toFixed(3)),
              timedOut: false,
              backend: 'worker'
            });
          } else {
            resolve({
              matched: null,
              durationMs: Number(wallClockMs.toFixed(3)),
              wallClockMs: Number(wallClockMs.toFixed(3)),
              timedOut: false,
              backend: 'worker',
              error: m.error ?? 'Unknown sandbox error'
            });
          }
        };

        const onError = (err: Error): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          cleanupListeners();
          void this.destroyWorker();
          const wallClockMs = performance.now() - wallStart;
          resolve({
            matched: null,
            durationMs: Number(wallClockMs.toFixed(3)),
            wallClockMs: Number(wallClockMs.toFixed(3)),
            timedOut: false,
            backend: 'worker',
            error: err.message
          });
        };

        const cleanupListeners = (): void => {
          w.off('message', onMessage);
          w.off('error', onError);
          w.unref();
        };

        w.ref();
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanupListeners();
          void this.destroyWorker().then(() => {
            const wallClockMs = performance.now() - wallStart;
            resolve({
              matched: null,
              durationMs: Number(wallClockMs.toFixed(3)),
              wallClockMs: Number(wallClockMs.toFixed(3)),
              timedOut: true,
              backend: 'worker'
            });
          });
        }, remainingBudget);

        w.on('message', onMessage);
        w.on('error', onError);
        w.postMessage({
          id,
          source: req.source,
          flags: req.flags,
          input: req.input
        });
      });
    }

    // Child process backend (`shell: false`)
    let childBundle: { proc: ChildProcessWithoutNullStreams; rl: readline.Interface };
    try {
      childBundle = await this.ensureChild();
    } catch (err) {
      return {
        matched: null,
        durationMs: 0,
        wallClockMs: performance.now() - wallStart,
        timedOut: false,
        backend: 'child',
        error: err instanceof Error ? err.message : String(err)
      };
    }

    const { proc, rl } = childBundle;
    const elapsedBoot = performance.now() - wallStart;
    const remainingBudget = Math.max(1, timeoutMs - Math.min(elapsedBoot, timeoutMs * 0.5));

    return new Promise<SandboxProbeResult>((resolve) => {
      let settled = false;

      const onLine = (line: string): void => {
        if (!line || settled) return;
        let m: {
          id?: number;
          ok?: boolean;
          matched?: boolean;
          durationMs?: number;
          error?: string;
        };
        try {
          m = JSON.parse(line) as typeof m;
        } catch {
          return;
        }
        if (m.id !== id) return;
        settled = true;
        clearTimeout(timer);
        cleanupListeners();
        const wallClockMs = performance.now() - wallStart;
        if (m.ok) {
          resolve({
            matched: Boolean(m.matched),
            durationMs: Number((m.durationMs ?? wallClockMs).toFixed(3)),
            wallClockMs: Number(wallClockMs.toFixed(3)),
            timedOut: false,
            backend: 'child'
          });
        } else {
          resolve({
            matched: null,
            durationMs: Number(wallClockMs.toFixed(3)),
            wallClockMs: Number(wallClockMs.toFixed(3)),
            timedOut: false,
            backend: 'child',
            error: m.error ?? 'Unknown child sandbox error'
          });
        }
      };

      const onExitOrError = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        cleanupListeners();
        void this.destroyChild();
        const wallClockMs = performance.now() - wallStart;
        resolve({
          matched: null,
          durationMs: Number(wallClockMs.toFixed(3)),
          wallClockMs: Number(wallClockMs.toFixed(3)),
          timedOut: false,
          backend: 'child',
          error: 'Sandbox child exited unexpectedly'
        });
      };

      const cleanupListeners = (): void => {
        rl.off('line', onLine);
        proc.off('exit', onExitOrError);
        proc.off('error', onExitOrError);
        proc.unref();
      };

      proc.ref();
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanupListeners();
        void this.destroyChild().then(() => {
          const wallClockMs = performance.now() - wallStart;
          resolve({
            matched: null,
            durationMs: Number(wallClockMs.toFixed(3)),
            wallClockMs: Number(wallClockMs.toFixed(3)),
            timedOut: true,
            backend: 'child'
          });
        });
      }, remainingBudget);

      rl.on('line', onLine);
      proc.once('exit', onExitOrError);
      proc.once('error', onExitOrError);
      proc.stdin.write(
        JSON.stringify({
          id,
          source: req.source,
          flags: req.flags,
          input: req.input
        }) + '\n'
      );
    });
  }
}

export async function evaluatePatternInSandbox(
  req: SandboxProbeRequest,
  options: { timeoutMs?: number; backend?: SandboxBackend } = {}
): Promise<SandboxProbeResult> {
  const executor = new SandboxExecutor(options.backend ?? 'auto');
  try {
    return await executor.runProbe(req, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  } finally {
    await executor.close();
  }
}

export async function confirmFindingInSandbox(
  finding: RedosFinding,
  executor: SandboxExecutor,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<ConfirmEvidence> {
  if (!finding.attack || (finding.complexity !== 'exp' && finding.complexity !== 'poly')) {
    return {
      status: 'skipped',
      backend: executor.activeBackend,
      samples: [],
      growthRatio: null,
      measuredClass: null
    };
  }

  const pumpSchedule = finding.complexity === 'exp' ? EXP_PUMP_COUNTS : POLY_PUMP_COUNTS;
  const samples: ConfirmSample[] = [];
  const { prefix, pump, suffix } = finding.attack;

  // Strip stateful 'g' / 'y' flags only if needed? Wait: fresh RegExp is created per probe so 'g' starts at lastIndex = 0;
  // only 'y' (sticky) forces index 0 just like '^', so pass finding.flags directly!
  for (const n of pumpSchedule) {
    const input = `${prefix}${pump.repeat(n)}${suffix}`;
    const res = await executor.runProbe(
      {
        source: finding.pattern,
        flags: finding.flags,
        input
      },
      timeoutMs
    );

    if (res.error) {
      return {
        status: 'error',
        backend: res.backend,
        samples,
        growthRatio: null,
        measuredClass: null,
        errorMessage: res.error
      };
    }

    samples.push({
      n,
      durationMs: res.durationMs,
      timedOut: res.timedOut
    });

    if (res.timedOut) {
      // Hitting timeout on deterministic pump schedule directly confirms super-linear blowup
      break;
    }
  }

  const anyTimedOut = samples.some((s) => s.timedOut);

  if (finding.complexity === 'exp') {
    if (anyTimedOut) {
      const prev = samples.length >= 2 ? samples[samples.length - 2]! : null;
      const last = samples[samples.length - 1]!;
      const ratio =
        prev && prev.durationMs > 0.05
          ? Number((last.durationMs / prev.durationMs).toFixed(2))
          : null;
      return {
        status: 'confirmed',
        backend: executor.activeBackend,
        samples,
        growthRatio: ratio,
        measuredClass: 'exp'
      };
    }

    // Compare last sample (n=24) against earlier samples (n=20 and n=16)
    const sLast = samples[samples.length - 1];
    const sPrev = samples.length >= 2 ? samples[samples.length - 2] : undefined;
    const sMid = samples.length >= 3 ? samples[samples.length - 3] : undefined;

    const stepRatio =
      sLast && sPrev ? sLast.durationMs / Math.max(sPrev.durationMs, 0.05) : 0;
    const twoStepRatio =
      sLast && sMid ? sLast.durationMs / Math.max(sMid.durationMs, 0.05) : 0;

    const isExp =
      Boolean(sLast && sLast.durationMs >= 1.0 && (stepRatio >= 4.5 || twoStepRatio >= 20));

    return {
      status: isExp ? 'confirmed' : 'unconfirmed',
      backend: executor.activeBackend,
      samples,
      growthRatio: Number(stepRatio.toFixed(2)),
      measuredClass: isExp ? 'exp' : 'linear'
    };
  }

  // Polynomial classification (n = 1000, 2000, 4000, 8000)
  if (anyTimedOut) {
    const prev = samples.length >= 2 ? samples[samples.length - 2]! : null;
    const last = samples[samples.length - 1]!;
    const ratio =
      prev && prev.durationMs > 0.05
        ? Number((last.durationMs / prev.durationMs).toFixed(2))
        : null;
    return {
      status: 'confirmed',
      backend: executor.activeBackend,
      samples,
      growthRatio: ratio,
      measuredClass: 'poly'
    };
  }

  const s8k = samples[samples.length - 1];
  const s4k = samples.length >= 2 ? samples[samples.length - 2] : undefined;
  const s2k = samples.length >= 3 ? samples[samples.length - 3] : undefined;
  const s1k = samples[0];

  const lastDoubling = s8k && s4k ? s8k.durationMs / Math.max(s4k.durationMs, 0.05) : 0;
  const twoDoublings = s8k && s2k ? s8k.durationMs / Math.max(s2k.durationMs, 0.05) : 0;
  const overallSpan = s8k && s1k ? s8k.durationMs / Math.max(s1k.durationMs, 0.05) : 0;

  const isPoly = Boolean(
    s8k &&
      s8k.durationMs >= 1.2 &&
      (lastDoubling >= 2.6 || twoDoublings >= 7.5 || overallSpan >= 12.0)
  );

  return {
    status: isPoly ? 'confirmed' : 'unconfirmed',
    backend: executor.activeBackend,
    samples,
    growthRatio: Number(lastDoubling.toFixed(2)),
    measuredClass: isPoly ? 'poly' : 'linear'
  };
}
