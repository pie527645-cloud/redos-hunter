#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBaselineFingerprints } from './analyzer/fingerprint.js';
import { explainPattern } from './analyzer/staticAnalyzer.js';
import {
  formatCheckReport,
  formatExplainReport,
  PACKAGE_VERSION
} from './formatters/reportFormatter.js';
import { DEFAULT_TIMEOUT_MS } from './sandbox/sandboxRunner.js';
import {
  doesFindingTriggerFailOn,
  runWorkspaceCheck
} from './scanner/workspaceScanner.js';
import {
  MAX_PATTERN_LENGTH,
  RedosHunterError,
  UsageError
} from './security/pathGuard.js';
import type {
  OutputFormat,
  Severity,
  SupportedLanguage
} from './types.js';

export interface CliIo {
  stdout: (msg: string) => void;
  stderr: (msg: string) => void;
}

const DEFAULT_IO: CliIo = {
  stdout: (msg) => process.stdout.write(msg + '\n'),
  stderr: (msg) => process.stderr.write(msg + '\n')
};

const VALID_LANGUAGES = new Set<string>(['js', 'ts', 'json', 'yaml']);
const VALID_FORMATS = new Set<string>(['pretty', 'json', 'markdown', 'sarif']);
const VALID_SEVERITIES = new Set<string>(['info', 'low', 'medium', 'high']);

export function isMainModule(
  metaUrl: string,
  argv1: string | undefined = process.argv[1]
): boolean {
  if (!argv1) {
    return false;
  }
  const selfPath = fileURLToPath(metaUrl);
  try {
    const invokedCanonical = fs.realpathSync(path.resolve(argv1));
    const selfCanonical = fs.realpathSync(selfPath);
    return invokedCanonical === selfCanonical;
  } catch {
    return path.resolve(argv1) === path.resolve(selfPath);
  }
}

function getMainHelpText(): string {
  return [
    'Usage: redos-hunter <command> [options]',
    '',
    'Commands:',
    '  check [paths..]       Scan JS/TS/JSON/YAML files for catastrophic ReDoS patterns',
    '  explain "<pattern>"   Inspect regex AST, interval ambiguity, attack string, and linear rewrite',
    '',
    'Global Options:',
    '  -h, --help            Display help information',
    '  -v, --version         Display package version'
  ].join('\n');
}

function getCheckHelpText(): string {
  return [
    'Usage: redos-hunter check [paths..] [--lang js,ts,json,yaml] [--confirm] [--timeout-ms 250] [--format pretty|json|markdown|sarif] [--fail-on info|low|medium|high] [--baseline <file>]',
    '',
    'Options:',
    '  --lang list           Comma-separated languages: js,ts,json,yaml (default: js,ts,json,yaml)',
    '  --confirm             Empirically verify static findings inside an isolated sandbox',
    '  --timeout-ms ms       Per-probe sandbox timeout in milliseconds (default: 250)',
    '  --format fmt          Output format: pretty, json, markdown, or sarif (default: pretty)',
    '  --fail-on level       Minimum severity causing exit code 1: info, low, medium, or high (default: high)',
    '  --baseline file       Suppress findings matching fingerprints from a baseline JSON/SARIF file',
    '  -h, --help            Display help for check'
  ].join('\n');
}

function getExplainHelpText(): string {
  return [
    'Usage: redos-hunter explain "<pattern>" [--flags gu] [--format pretty|json]',
    '',
    'Options:',
    '  --flags flags         Regular expression flags, e.g. gu, i, v (default: "")',
    '  --format fmt          Output format: pretty or json (default: pretty)',
    '  -h, --help            Display help for explain'
  ].join('\n');
}

function parseLanguagesList(raw: string): SupportedLanguage[] {
  const parts = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  if (parts.length === 0) {
    throw new UsageError('--lang requires at least one language (js,ts,json,yaml).');
  }
  const out: SupportedLanguage[] = [];
  for (const p of parts) {
    if (!VALID_LANGUAGES.has(p)) {
      throw new UsageError(
        `Unsupported language '${p}' in --lang. Supported v1 languages: js,ts,json,yaml.`
      );
    }
    if (!out.includes(p as SupportedLanguage)) {
      out.push(p as SupportedLanguage);
    }
  }
  return out;
}

async function handleCheckCommand(args: string[], io: CliIo, cwd: string): Promise<number> {
  const paths: string[] = [];
  let languages: SupportedLanguage[] = ['js', 'ts', 'json', 'yaml'];
  let confirm = false;
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  let format: OutputFormat = 'pretty';
  let failOn: Severity = 'high';
  let baselineFile: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '-h' || arg === '--help') {
      io.stdout(getCheckHelpText());
      return 0;
    }
    if (arg === '--confirm') {
      confirm = true;
      continue;
    }
    if (arg === '--lang' || arg.startsWith('--lang=')) {
      const val = arg === '--lang' ? args[++i] : arg.slice('--lang='.length);
      if (!val) {
        io.stderr('Error: --lang requires a comma-separated list (js,ts,json,yaml).');
        return 2;
      }
      languages = parseLanguagesList(val);
      continue;
    }
    if (arg === '--timeout-ms' || arg.startsWith('--timeout-ms=')) {
      const val = arg === '--timeout-ms' ? args[++i] : arg.slice('--timeout-ms='.length);
      if (!val || !/^\d+$/.test(val)) {
        io.stderr('Error: --timeout-ms must be a positive integer (1..60000).');
        return 2;
      }
      const parsed = Number.parseInt(val, 10);
      if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 60_000) {
        io.stderr('Error: --timeout-ms must be between 1 and 60000.');
        return 2;
      }
      timeoutMs = parsed;
      continue;
    }
    if (arg === '--format' || arg.startsWith('--format=')) {
      const val = arg === '--format' ? args[++i] : arg.slice('--format='.length);
      if (!val || !VALID_FORMATS.has(val)) {
        io.stderr('Error: --format must be pretty, json, markdown, or sarif.');
        return 2;
      }
      format = val as OutputFormat;
      continue;
    }
    if (arg === '--fail-on' || arg.startsWith('--fail-on=')) {
      const val = arg === '--fail-on' ? args[++i] : arg.slice('--fail-on='.length);
      if (!val || !VALID_SEVERITIES.has(val)) {
        io.stderr('Error: --fail-on must be info, low, medium, or high.');
        return 2;
      }
      failOn = val as Severity;
      continue;
    }
    if (arg === '--baseline' || arg.startsWith('--baseline=')) {
      const val = arg === '--baseline' ? args[++i] : arg.slice('--baseline='.length);
      if (!val) {
        io.stderr('Error: --baseline requires a path to a baseline file.');
        return 2;
      }
      baselineFile = val;
      continue;
    }
    if (arg === '--') {
      for (let j = i + 1; j < args.length; j++) {
        paths.push(args[j]!);
      }
      break;
    }
    if (arg.startsWith('-')) {
      io.stderr(`Error: Unknown option '${arg}' for check.`);
      return 2;
    }
    paths.push(arg);
  }

  const baselineFingerprints =
    baselineFile !== undefined
      ? loadBaselineFingerprints(path.resolve(cwd, baselineFile))
      : undefined;

  const report = await runWorkspaceCheck({
    paths: paths.length > 0 ? paths : [cwd],
    cwd,
    languages,
    confirm,
    timeoutMs,
    ...(baselineFingerprints !== undefined ? { baselineFingerprints } : {})
  });

  io.stdout(formatCheckReport(report, format));

  const shouldFail = report.findings.some((f) => doesFindingTriggerFailOn(f.severity, failOn));
  return shouldFail ? 1 : 0;
}

function handleExplainCommand(args: string[], io: CliIo): number {
  let pattern: string | undefined;
  let flags = '';
  let format: 'pretty' | 'json' = 'pretty';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '-h' || arg === '--help') {
      io.stdout(getExplainHelpText());
      return 0;
    }
    if (arg === '--flags' || arg.startsWith('--flags=')) {
      const val = arg === '--flags' ? args[++i] : arg.slice('--flags='.length);
      if (val === undefined) {
        io.stderr('Error: --flags requires a flags string (e.g. gu).');
        return 2;
      }
      flags = val;
      continue;
    }
    if (arg === '--format' || arg.startsWith('--format=')) {
      const val = arg === '--format' ? args[++i] : arg.slice('--format='.length);
      if (val !== 'pretty' && val !== 'json') {
        io.stderr('Error: --format for explain must be pretty or json.');
        return 2;
      }
      format = val;
      continue;
    }
    if (arg === '--') {
      const rem = args.slice(i + 1);
      if (rem.length > 0 && pattern === undefined) {
        pattern = rem[0]!;
        if (rem.length > 1) {
          io.stderr(`Error: Unexpected extra positional argument '${rem[1]}'.`);
          return 2;
        }
      }
      break;
    }
    if (arg.startsWith('-') && pattern === undefined) {
      io.stderr(`Error: Unknown option '${arg}' for explain.`);
      return 2;
    }
    if (pattern !== undefined) {
      io.stderr(`Error: Unexpected positional argument '${arg}'.`);
      return 2;
    }
    pattern = arg;
  }

  if (pattern === undefined) {
    io.stderr('Error: explain requires a "<pattern>" argument.');
    return 2;
  }

  if (pattern.length > MAX_PATTERN_LENGTH) {
    io.stderr(`Error: Pattern exceeds maximum length of ${MAX_PATTERN_LENGTH} characters.`);
    return 2;
  }

  try {
    const explained = explainPattern(pattern, flags);
    io.stdout(formatExplainReport(explained, format));
    return 0;
  } catch (err) {
    io.stderr(`Error: Invalid regular expression: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

export async function runCli(
  argv: string[],
  io: CliIo = DEFAULT_IO,
  cwd: string = process.cwd()
): Promise<number> {
  if (argv.length === 0) {
    io.stdout(getMainHelpText());
    return 0;
  }

  const first = argv[0]!;
  if (first === '-h' || first === '--help') {
    io.stdout(getMainHelpText());
    return 0;
  }
  if (first === '-v' || first === '--version') {
    io.stdout(PACKAGE_VERSION);
    return 0;
  }

  const rest = argv.slice(1);
  try {
    if (first === 'check') {
      return await handleCheckCommand(rest, io, cwd);
    }
    if (first === 'explain') {
      return handleExplainCommand(rest, io);
    }
    io.stderr(`Error: Unknown command '${first}'. Run 'redos-hunter --help' for usage.`);
    return 2;
  } catch (err) {
    if (err instanceof RedosHunterError) {
      io.stderr(`Error (${err.code}): ${err.message}`);
      return err.exitCode;
    }
    io.stderr(`Error: ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }
}

if (isMainModule(import.meta.url)) {
  runCli(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 2;
    }
  );
}
