export type Severity = 'info' | 'low' | 'medium' | 'high';

export type RuleId =
  | 'RDH001'
  | 'RDH002'
  | 'RDH003'
  | 'RDH005'
  | 'RDH006'
  | 'RDH007'
  | 'RDH900'
  | 'RDH901'
  | 'RDH902'
  | 'RDH903'
  | 'RDH904';

export type ComplexityClass = 'exp' | 'poly' | 'warning' | 'info';

export type SupportedLanguage = 'js' | 'ts' | 'json' | 'yaml';

export type OutputFormat = 'pretty' | 'json' | 'markdown' | 'sarif';

export type SandboxBackend = 'auto' | 'worker' | 'child';

export interface AttackSpec {
  prefix: string;
  pump: string;
  suffix: string;
  recommendedRepetitions: number;
  preview: string;
}

export interface FixHint {
  summary: string;
  rewrite: string | null;
  rewriteFlags?: string;
  notes?: string;
}

export interface ConfirmSample {
  n: number;
  durationMs: number;
  timedOut: boolean;
}

export interface ConfirmEvidence {
  status: 'confirmed' | 'unconfirmed' | 'skipped' | 'error';
  backend: 'worker' | 'child';
  samples: ConfirmSample[];
  growthRatio: number | null;
  measuredClass: 'exp' | 'poly' | 'linear' | null;
  errorMessage?: string;
}

export interface RedosFinding {
  ruleId: RuleId;
  severity: Severity;
  complexity: ComplexityClass;
  message: string;
  file: string;
  line: number;
  column: number;
  pattern: string;
  flags: string;
  span: {
    start: number;
    end: number;
  };
  overlapSummary?: string;
  attack?: AttackSpec;
  fix?: FixHint;
  fingerprint: string;
  evidence?: ConfirmEvidence;
}

export interface ExtractedPattern {
  pattern: string;
  flags: string;
  file: string;
  line: number;
  column: number;
  language: SupportedLanguage;
  origin: 'regex-literal' | 'regexp-constructor' | 'schema-pattern' | 'schema-pattern-property';
}

export interface ExtractionDiagnostic {
  ruleId: 'RDH900' | 'RDH901' | 'RDH902' | 'RDH903';
  message: string;
  file: string;
  line: number;
  column: number;
  pattern?: string;
  flags?: string;
}

export interface CheckOptions {
  paths?: string[];
  cwd?: string;
  languages?: SupportedLanguage[];
  confirm?: boolean;
  timeoutMs?: number;
  backend?: SandboxBackend;
  baselineFingerprints?: ReadonlySet<string>;
  maxFileBytes?: number;
  maxPatternLength?: number;
  maxPatternsPerRun?: number;
}

export interface CheckReport {
  scannedFilesCount: number;
  extractedPatternsCount: number;
  suppressedCount: number;
  findings: RedosFinding[];
}

export interface ExplainResult {
  pattern: string;
  flags: string;
  astSummary: string[];
  findings: RedosFinding[];
}
