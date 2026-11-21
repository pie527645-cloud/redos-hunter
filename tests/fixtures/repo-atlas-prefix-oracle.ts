/**
 * Self-contained regression oracle containing the verbatim pre-fix ReDoS patterns
 * from repo-atlas (prior to commit 15ad1fb) and nested delimiter/quantifier traps.
 * Never executed; scanned statically and in isolated sandbox by redos-hunter tests.
 */

export function legacyNormalizeGitignoreBase(baseDirPosix: string): string {
  return baseDirPosix.replace(/^\/+|\/+$/g, '');
}

export function legacyNormalizeTsconfigBaseUrl(rawBaseUrl: string): string {
  return rawBaseUrl.replace(/^\/+|\/+$/g, '');
}

export const LEGACY_PATH_SEGMENTS_REGEX = /^(\w+\/?)+$/;

export const LEGACY_NESTED_QUANTIFIER_REGEX = /(a+)+$/;
