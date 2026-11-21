export * from './types.js';
export {
  BMP_MAX,
  UNICODE_MAX,
  complementSet,
  EMPTY_SET,
  expandIgnoreCase,
  formatIntervalSummary,
  fullSet,
  intersectSets,
  isEmptySet,
  isSubset,
  normalizeIntervals,
  pickNonMatchingString,
  pickWitnessCodePoint,
  pickWitnessString,
  rangeSet,
  setContains,
  setsEqual,
  setsOverlap,
  singletonSet,
  subtractSets,
  unionSets,
  type CodePointSet,
  type EffectiveFlags,
  type Interval
} from './analyzer/charSet.js';
export {
  computeFingerprint,
  loadBaselineFingerprints
} from './analyzer/fingerprint.js';
export { CANONICAL_REWRITE_CATALOG } from './analyzer/fixHints.js';
export {
  analyzePattern,
  explainPattern,
  parseRegexAst
} from './analyzer/staticAnalyzer.js';
export { extractFromJsTs } from './extractor/jsExtractor.js';
export { extractFromSchemaContent } from './extractor/schemaExtractor.js';
export {
  confirmFindingInSandbox,
  DEFAULT_TIMEOUT_MS,
  evaluatePatternInSandbox,
  EXP_PUMP_COUNTS,
  POLY_PUMP_COUNTS,
  resolveDefaultBackend,
  SandboxExecutor,
  type SandboxProbeRequest,
  type SandboxProbeResult
} from './sandbox/sandboxRunner.js';
export {
  doesFindingTriggerFailOn,
  runWorkspaceCheck
} from './scanner/workspaceScanner.js';
export {
  formatCheckReport,
  formatExplainReport,
  formatSarifReport,
  INFORMATION_URI,
  PACKAGE_VERSION
} from './formatters/reportFormatter.js';
export {
  MAX_FILE_BYTES,
  MAX_PATTERN_LENGTH,
  MAX_PATTERNS_PER_RUN,
  MAX_YAML_ALIASES,
  PathSecurityError,
  RedosHunterError,
  resolveCanonicalRoot,
  resolveContainedPath,
  UsageError,
  YamlSecurityError
} from './security/pathGuard.js';
