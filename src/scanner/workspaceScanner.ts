import { computeFingerprint } from '../analyzer/fingerprint.js';
import { analyzePattern } from '../analyzer/staticAnalyzer.js';
import { extractFromJsTs } from '../extractor/jsExtractor.js';
import { extractFromSchemaContent } from '../extractor/schemaExtractor.js';
import {
  confirmFindingInSandbox,
  DEFAULT_TIMEOUT_MS,
  SandboxExecutor
} from '../sandbox/sandboxRunner.js';
import {
  discoverFilesInTarget,
  MAX_FILE_BYTES,
  MAX_PATTERN_LENGTH,
  MAX_PATTERNS_PER_RUN,
  readBoundedFile
} from '../security/pathGuard.js';
import type {
  CheckOptions,
  CheckReport,
  ExtractionDiagnostic,
  RedosFinding,
  Severity,
  SupportedLanguage
} from '../types.js';

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3
};

export function doesFindingTriggerFailOn(severity: Severity, failOn: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[failOn];
}

function diagnosticToFinding(diag: ExtractionDiagnostic): RedosFinding {
  const pattern = diag.pattern ?? '';
  const flags = diag.flags ?? '';
  const span = { start: 0, end: pattern.length };
  return {
    ruleId: diag.ruleId,
    severity: 'info',
    complexity: 'info',
    message: diag.message,
    file: diag.file,
    line: diag.line,
    column: diag.column,
    pattern,
    flags,
    span,
    fingerprint: computeFingerprint({
      ruleId: diag.ruleId,
      file: diag.file,
      pattern,
      flags,
      span
    })
  };
}

export async function runWorkspaceCheck(options: CheckOptions = {}): Promise<CheckReport> {
  const cwd = options.cwd ?? process.cwd();
  const targets = options.paths && options.paths.length > 0 ? options.paths : [cwd];
  const allowedLangs = new Set<SupportedLanguage>(
    options.languages ?? ['js', 'ts', 'json', 'yaml']
  );
  const maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
  const maxPatternLength = options.maxPatternLength ?? MAX_PATTERN_LENGTH;
  const maxPatternsPerRun = options.maxPatternsPerRun ?? MAX_PATTERNS_PER_RUN;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const baseline = options.baselineFingerprints;

  const seenAbsoluteFiles = new Set<string>();
  const allDiscovered: Array<{
    absolutePath: string;
    displayPath: string;
    language: SupportedLanguage;
  }> = [];

  for (const target of targets) {
    const { files } = discoverFilesInTarget(target, cwd, allowedLangs);
    for (const f of files) {
      const key = process.platform === 'win32' || process.platform === 'darwin'
        ? f.absolutePath.toLowerCase()
        : f.absolutePath;
      if (!seenAbsoluteFiles.has(key)) {
        seenAbsoluteFiles.add(key);
        allDiscovered.push(f);
      }
    }
  }

  let scannedFilesCount = 0;
  let extractedPatternsCount = 0;
  let capReachedEmitted = false;
  const rawFindings: RedosFinding[] = [];

  for (const fileInfo of allDiscovered) {
    const readRes = readBoundedFile(fileInfo.absolutePath, maxFileBytes);
    if (readRes.status === 'too_large') {
      rawFindings.push(
        diagnosticToFinding({
          ruleId: 'RDH902',
          message: `File size (${readRes.byteLength} bytes) exceeds ${maxFileBytes} bytes cap and was skipped.`,
          file: fileInfo.displayPath,
          line: 1,
          column: 1
        })
      );
      continue;
    }
    if (readRes.status !== 'ok') {
      continue;
    }

    scannedFilesCount++;

    const extraction =
      fileInfo.language === 'js' || fileInfo.language === 'ts'
        ? extractFromJsTs(readRes.content, fileInfo.displayPath, fileInfo.language, maxPatternLength)
        : extractFromSchemaContent(readRes.content, fileInfo.displayPath, fileInfo.language, {
            maxPatternLength
          });

    for (const diag of extraction.diagnostics) {
      rawFindings.push(diagnosticToFinding(diag));
    }

    for (const extPat of extraction.patterns) {
      if (extractedPatternsCount >= maxPatternsPerRun) {
        if (!capReachedEmitted) {
          capReachedEmitted = true;
          rawFindings.push(
            diagnosticToFinding({
              ruleId: 'RDH903',
              message: `Maximum pattern count per run (${maxPatternsPerRun}) reached; remaining patterns were skipped.`,
              file: extPat.file,
              line: extPat.line,
              column: extPat.column
            })
          );
        }
        break;
      }

      extractedPatternsCount++;
      const patFindings = analyzePattern(extPat.pattern, extPat.flags, {
        file: extPat.file,
        line: extPat.line,
        column: extPat.column
      });
      for (const f of patFindings) {
        rawFindings.push(f);
      }
    }
  }

  // Apply baseline suppression before running empirical confirmation so suppressed findings don't spend sandbox time
  let suppressedCount = 0;
  const activeFindings: RedosFinding[] = [];
  for (const f of rawFindings) {
    if (baseline && baseline.has(f.fingerprint)) {
      suppressedCount++;
      continue;
    }
    activeFindings.push(f);
  }

  // Deterministic sort: severity descending, then file, line, column, ruleId
  activeFindings.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.line !== b.line) return a.line - b.line;
    if (a.column !== b.column) return a.column - b.column;
    return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
  });

  if (options.confirm && activeFindings.length > 0) {
    const executor = new SandboxExecutor(options.backend ?? 'auto');
    try {
      for (const finding of activeFindings) {
        finding.evidence = await confirmFindingInSandbox(finding, executor, timeoutMs);
        // Spec invariant: empirical timing NEVER downgrades static severity or alters fingerprint
      }
    } finally {
      await executor.close();
    }
  }

  return {
    scannedFilesCount,
    extractedPatternsCount,
    suppressedCount,
    findings: activeFindings
  };
}
