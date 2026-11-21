import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { UsageError } from '../security/pathGuard.js';
import type { RuleId } from '../types.js';

export function computeFingerprint(input: {
  ruleId: RuleId;
  file: string;
  pattern: string;
  flags: string;
  span: { start: number; end: number };
}): string {
  const normalizedFile = input.file.split('\\').join('/');
  const payload = JSON.stringify([
    input.ruleId,
    normalizedFile,
    input.pattern,
    input.flags,
    input.span.start,
    input.span.end
  ]);
  return createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32);
}

export function loadBaselineFingerprints(baselinePath: string): Set<string> {
  let raw: string;
  try {
    raw = fs.readFileSync(baselinePath, 'utf8');
  } catch (err) {
    throw new UsageError(
      `Unable to read baseline file '${baselinePath}': ${err instanceof Error ? err.message : String(err)}`,
      'BASELINE_READ_ERROR'
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw);
  } catch (err) {
    throw new UsageError(
      `Invalid JSON in baseline file '${baselinePath}': ${err instanceof Error ? err.message : String(err)}`,
      'BASELINE_PARSE_ERROR'
    );
  }

  const out = new Set<string>();

  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (typeof item === 'string') {
        out.add(item);
      } else if (item && typeof item === 'object' && 'fingerprint' in item) {
        const fp = (item as { fingerprint?: unknown }).fingerprint;
        if (typeof fp === 'string') {
          out.add(fp);
        }
      }
    }
    return out;
  }

  if (parsed && typeof parsed === 'object') {
    const obj = parsed as Record<string, unknown>;
    if (Array.isArray(obj['fingerprints'])) {
      for (const fp of obj['fingerprints']) {
        if (typeof fp === 'string') {
          out.add(fp);
        }
      }
    }
    if (Array.isArray(obj['findings'])) {
      for (const f of obj['findings']) {
        if (f && typeof f === 'object' && 'fingerprint' in f) {
          const fp = (f as { fingerprint?: unknown }).fingerprint;
          if (typeof fp === 'string') {
            out.add(fp);
          }
        }
      }
    }
    // Also support SARIF 2.1.0 baseline files (`runs[].results[].partialFingerprints`)
    if (Array.isArray(obj['runs'])) {
      for (const run of obj['runs']) {
        if (run && typeof run === 'object' && Array.isArray((run as Record<string, unknown>)['results'])) {
          const results = (run as { results: unknown[] }).results;
          for (const res of results) {
            if (res && typeof res === 'object' && 'partialFingerprints' in res) {
              const pfp = (res as { partialFingerprints?: Record<string, unknown> }).partialFingerprints;
              if (pfp && typeof pfp === 'object') {
                for (const val of Object.values(pfp)) {
                  if (typeof val === 'string') {
                    out.add(val);
                  }
                }
              }
            }
          }
        }
      }
    }
    return out;
  }

  throw new UsageError(
    `Unsupported baseline format in '${baselinePath}'. Expected JSON array, check report, or SARIF log.`,
    'BASELINE_FORMAT_ERROR'
  );
}
