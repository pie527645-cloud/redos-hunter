import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SupportedLanguage } from '../types.js';

export const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB per file cap
export const MAX_PATTERN_LENGTH = 64 * 1024; // 64 KB per pattern cap
export const MAX_PATTERNS_PER_RUN = 10_000;
export const MAX_YAML_ALIASES = 100;
export const MAX_PATH_LENGTH = 1024;

const CASE_INSENSITIVE_FS = process.platform === 'win32' || process.platform === 'darwin';

const IGNORED_DIR_NAMES = new Set<string>([
  '.git',
  'node_modules',
  'dist',
  'dist-test',
  'dist-tests',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  'vendor',
  '__pycache__',
  '.venv',
  'venv'
]);

export class RedosHunterError extends Error {
  public readonly code: string;
  public readonly exitCode: number;

  constructor(message: string, code = 'REDOS_HUNTER_ERROR', exitCode = 2) {
    super(message);
    this.name = 'RedosHunterError';
    this.code = code;
    this.exitCode = exitCode;
  }
}

export class PathSecurityError extends RedosHunterError {
  constructor(message: string, code = 'PATH_SECURITY_ERROR') {
    super(message, code, 2);
    this.name = 'PathSecurityError';
  }
}

export class UsageError extends RedosHunterError {
  constructor(message: string, code = 'USAGE_ERROR') {
    super(message, code, 2);
    this.name = 'UsageError';
  }
}

export class YamlSecurityError extends RedosHunterError {
  constructor(message: string, code = 'YAML_ALIAS_LIMIT') {
    super(message, code, 2);
    this.name = 'YamlSecurityError';
  }
}

export function hasInvalidPathChars(input: string): boolean {
  if (!input || input.length > MAX_PATH_LENGTH) {
    return true;
  }
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function isUncOrSchemePath(input: string): boolean {
  if (input.startsWith('\\\\') || input.startsWith('//')) {
    return true;
  }
  const colonIdx = input.indexOf(':');
  if (colonIdx > 1) {
    return true;
  }
  if (colonIdx === 1 && input.indexOf(':', 2) !== -1) {
    return true;
  }
  return false;
}

function normalizeForComparison(p: string): string {
  const resolved = path.resolve(p);
  return CASE_INSENSITIVE_FS ? resolved.toLowerCase() : resolved;
}

export function isWithinRoot(canonicalRoot: string, candidatePath: string): boolean {
  const normRoot = normalizeForComparison(canonicalRoot);
  const normCand = normalizeForComparison(candidatePath);
  const rel = path.relative(normRoot, normCand);
  if (rel === '') {
    return true;
  }
  if (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) {
    return false;
  }
  return true;
}

export function resolveCanonicalRoot(rootPath: string): { canonicalPath: string; isFile: boolean } {
  if (hasInvalidPathChars(rootPath)) {
    throw new PathSecurityError('Invalid target path.', 'INVALID_PATH');
  }
  if (isUncOrSchemePath(rootPath)) {
    throw new PathSecurityError('UNC, URL scheme, and alternate data stream paths are blocked.', 'UNC_BLOCKED');
  }
  let lstat: fs.Stats;
  try {
    lstat = fs.lstatSync(rootPath);
  } catch {
    throw new PathSecurityError(`Target path does not exist: ${rootPath}`, 'NOT_FOUND');
  }
  let realPath: string;
  try {
    realPath = fs.realpathSync.native(rootPath);
  } catch {
    throw new PathSecurityError(`Failed to resolve canonical path: ${rootPath}`, 'REALPATH_FAILED');
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(realPath);
  } catch {
    throw new PathSecurityError(`Target path is unreadable: ${rootPath}`, 'STAT_FAILED');
  }
  if (!stat.isDirectory() && !stat.isFile()) {
    throw new PathSecurityError(`Target path must be a regular file or directory: ${rootPath}`, 'INVALID_TARGET');
  }
  // If user passed a direct symlink as a file target whose parent directory differs, enforce containment when rootDir is provided by caller
  void lstat;
  return { canonicalPath: realPath, isFile: stat.isFile() };
}

export function resolveContainedPath(canonicalRoot: string, targetSubpath: string): string {
  if (hasInvalidPathChars(targetSubpath)) {
    throw new PathSecurityError('Target path contains prohibited characters or exceeds length cap.', 'INVALID_PATH');
  }
  if (isUncOrSchemePath(targetSubpath)) {
    throw new PathSecurityError('UNC, URL scheme, or alternate data stream paths are blocked.', 'UNC_OR_SCHEME_BLOCKED');
  }

  if (targetSubpath.length >= 2 && targetSubpath.charCodeAt(1) === 0x3a) {
    const third = targetSubpath.length > 2 ? targetSubpath.charCodeAt(2) : 0;
    if (third !== 0x5c && third !== 0x2f) {
      throw new PathSecurityError('Drive-relative paths are blocked.', 'DRIVE_ESCAPE_BLOCKED');
    }
    if (canonicalRoot.slice(0, 2).toUpperCase() !== targetSubpath.slice(0, 2).toUpperCase()) {
      throw new PathSecurityError('Cross-drive path escapes scan root.', 'DRIVE_ESCAPE_BLOCKED');
    }
  }

  if (process.platform !== 'win32' && targetSubpath.includes('\\')) {
    const posixCheck = path.posix.normalize(targetSubpath.split('\\').join('/'));
    if (posixCheck === '..' || posixCheck.startsWith('../') || posixCheck.startsWith('/')) {
      throw new PathSecurityError('Path escapes scan root boundary.', 'PATH_TRAVERSAL_BLOCKED');
    }
  }

  const candidate = path.resolve(canonicalRoot, targetSubpath);
  if (!isWithinRoot(canonicalRoot, candidate)) {
    throw new PathSecurityError('Path escapes scan root boundary.', 'PATH_TRAVERSAL_BLOCKED');
  }

  let current = candidate;
  const trailingSegments: string[] = [];
  while (true) {
    try {
      fs.lstatSync(current);
      break;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) {
        throw new PathSecurityError('Unable to resolve path ancestor within scan root.', 'ANCESTOR_NOT_FOUND');
      }
      trailingSegments.push(path.basename(current));
      current = parent;
    }
  }

  let realExisting: string;
  try {
    realExisting = fs.realpathSync.native(current);
  } catch {
    throw new PathSecurityError('Failed to resolve canonical target path.', 'REALPATH_FAILED');
  }

  if (!isWithinRoot(canonicalRoot, realExisting)) {
    throw new PathSecurityError('Symlink target escapes scan root boundary.', 'SYMLINK_ESCAPE_BLOCKED');
  }

  trailingSegments.reverse();
  const finalResolved =
    trailingSegments.length > 0 ? path.join(realExisting, ...trailingSegments) : realExisting;

  if (!isWithinRoot(canonicalRoot, finalResolved)) {
    throw new PathSecurityError('Resolved path escapes scan root boundary.', 'PATH_TRAVERSAL_BLOCKED');
  }

  return finalResolved;
}

export function detectLanguageFromExtension(filePath: string): SupportedLanguage | null {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return 'js';
    case '.ts':
    case '.tsx':
    case '.mts':
    case '.cts':
      return 'ts';
    case '.json':
      return 'json';
    case '.yaml':
    case '.yml':
      return 'yaml';
    default:
      return null;
  }
}

export interface DiscoveredFile {
  absolutePath: string;
  displayPath: string;
  language: SupportedLanguage;
}

export function discoverFilesInTarget(
  targetInput: string,
  cwd: string,
  allowedLanguages: ReadonlySet<SupportedLanguage>
): { rootDir: string; files: DiscoveredFile[] } {
  if (hasInvalidPathChars(targetInput) || isUncOrSchemePath(targetInput)) {
    throw new PathSecurityError(`Invalid or prohibited target path: ${targetInput}`, 'INVALID_PATH');
  }

  const resolvedInput = path.resolve(cwd, targetInput);
  let inputLstat: fs.Stats;
  try {
    inputLstat = fs.lstatSync(resolvedInput);
  } catch {
    throw new PathSecurityError(`Target path does not exist: ${targetInput}`, 'NOT_FOUND');
  }

  // If targetInput is itself a symlink, check that if it was specified relative to cwd, check realpath exists
  let realTarget: string;
  try {
    realTarget = fs.realpathSync.native(resolvedInput);
  } catch {
    throw new PathSecurityError(`Broken symbolic link or unreadable path: ${targetInput}`, 'REALPATH_FAILED');
  }

  if (inputLstat.isSymbolicLink()) {
    // If targetInput is inside cwd, ensure symlink does not escape cwd
    const realCwd = fs.realpathSync.native(cwd);
    if (isWithinRoot(realCwd, resolvedInput) && !isWithinRoot(realCwd, realTarget)) {
      throw new PathSecurityError(
        `Symbolic link escapes workspace root: ${targetInput}`,
        'SYMLINK_ESCAPE_BLOCKED'
      );
    }
  }

  const targetStat = fs.statSync(realTarget);
  if (targetStat.isFile()) {
    const lang = detectLanguageFromExtension(realTarget);
    const parentRoot = path.dirname(realTarget);
    if (!lang || !allowedLanguages.has(lang)) {
      return { rootDir: parentRoot, files: [] };
    }
    return {
      rootDir: parentRoot,
      files: [
        {
          absolutePath: realTarget,
          displayPath: path.basename(realTarget),
          language: lang
        }
      ]
    };
  }

  if (!targetStat.isDirectory()) {
    throw new PathSecurityError(`Target path is neither a file nor a directory: ${targetInput}`, 'INVALID_TARGET');
  }

  const canonicalRoot = realTarget;
  const visitedDirs = new Set<string>([normalizeForComparison(canonicalRoot)]);
  const files: DiscoveredFile[] = [];

  function walk(currentDir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      const fullEntryPath = path.join(currentDir, entry.name);

      if (entry.isSymbolicLink()) {
        // Resolve symlink and strictly enforce containment within canonicalRoot
        let resolvedLink: string;
        try {
          resolvedLink = fs.realpathSync.native(fullEntryPath);
        } catch {
          continue;
        }
        if (!isWithinRoot(canonicalRoot, resolvedLink)) {
          // Block symlink/junction escape outside scan root
          continue;
        }
        let linkStat: fs.Stats;
        try {
          linkStat = fs.statSync(resolvedLink);
        } catch {
          continue;
        }
        if (linkStat.isDirectory()) {
          if (IGNORED_DIR_NAMES.has(entry.name)) {
            continue;
          }
          const normKey = normalizeForComparison(resolvedLink);
          if (visitedDirs.has(normKey)) {
            continue;
          }
          visitedDirs.add(normKey);
          walk(resolvedLink);
        } else if (linkStat.isFile()) {
          const lang = detectLanguageFromExtension(entry.name);
          if (lang && allowedLanguages.has(lang)) {
            files.push({
              absolutePath: resolvedLink,
              displayPath: toPosixRelative(canonicalRoot, fullEntryPath),
              language: lang
            });
          }
        }
        continue;
      }

      if (entry.isDirectory()) {
        if (IGNORED_DIR_NAMES.has(entry.name)) {
          continue;
        }
        let realSubdir: string;
        try {
          realSubdir = fs.realpathSync.native(fullEntryPath);
        } catch {
          continue;
        }
        if (!isWithinRoot(canonicalRoot, realSubdir)) {
          continue;
        }
        const normKey = normalizeForComparison(realSubdir);
        if (visitedDirs.has(normKey)) {
          continue;
        }
        visitedDirs.add(normKey);
        walk(realSubdir);
      } else if (entry.isFile()) {
        const lang = detectLanguageFromExtension(entry.name);
        if (lang && allowedLanguages.has(lang)) {
          files.push({
            absolutePath: fullEntryPath,
            displayPath: toPosixRelative(canonicalRoot, fullEntryPath),
            language: lang
          });
        }
      }
    }
  }

  walk(canonicalRoot);
  return { rootDir: canonicalRoot, files };
}

export function isBinaryBuffer(buf: Buffer): boolean {
  const checkLen = Math.min(buf.length, 4096);
  for (let i = 0; i < checkLen; i++) {
    if (buf[i] === 0x00) {
      return true;
    }
  }
  return false;
}

export function stripUtf8Bom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function readBoundedFile(
  filePath: string,
  maxBytes = MAX_FILE_BYTES
):
  | { status: 'ok'; content: string; byteLength: number }
  | { status: 'too_large'; byteLength: number }
  | { status: 'binary' | 'unreadable'; byteLength: number } {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return { status: 'unreadable', byteLength: 0 };
  }
  if (!stat.isFile()) {
    return { status: 'unreadable', byteLength: 0 };
  }
  if (stat.size > maxBytes) {
    return { status: 'too_large', byteLength: stat.size };
  }
  let buf: Buffer;
  try {
    buf = fs.readFileSync(filePath);
  } catch {
    return { status: 'unreadable', byteLength: 0 };
  }
  if (buf.length > maxBytes) {
    return { status: 'too_large', byteLength: buf.length };
  }
  if (isBinaryBuffer(buf)) {
    return { status: 'binary', byteLength: buf.length };
  }
  return {
    status: 'ok',
    content: stripUtf8Bom(buf.toString('utf8')),
    byteLength: buf.length
  };
}

export function toPosixRelative(canonicalRoot: string, targetPath: string): string {
  const rel = path.relative(canonicalRoot, targetPath);
  if (rel === '') {
    return '.';
  }
  return rel.split(path.sep).join('/');
}
