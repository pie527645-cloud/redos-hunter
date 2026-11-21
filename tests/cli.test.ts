import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { describe, it } from 'node:test';
import { INFORMATION_URI as EXPECTED_URI } from '../src/index.js';
import { isMainModule, runCli as execCli } from '../src/cli.js';

const THIS_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(THIS_DIR, '../..');
const DIST_CLI_PATH = path.join(REPO_ROOT, 'dist', 'cli.js');

function captureCli(argv: string[], cwd: string): Promise<{ code: number; out: string; err: string }> {
  const outChunks: string[] = [];
  const errChunks: string[] = [];
  return execCli(
    argv,
    {
      stdout: (m) => outChunks.push(m),
      stderr: (m) => errChunks.push(m)
    },
    cwd
  ).then((code) => ({
    code,
    out: outChunks.join('\n'),
    err: errChunks.join('\n')
  }));
}

describe('CLI commands, SARIF 2.1.0, --baseline, >2MB skip, and symlink security', () => {
  it('skips files > 2 MB with an RDH902 info finding', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redos-hunter-big-'));
    try {
      const bigBundle = path.join(tmpDir, 'bundle.min.js');
      // Write 2.1 MB file containing a regex that must not be parsed
      const content = '// ' + 'x'.repeat(2_150_000) + '\nconst r = /(a+)+$/;\n';
      fs.writeFileSync(bigBundle, content, 'utf8');

      const res = await captureCli(['check', tmpDir, '--format', 'json'], tmpDir);
      assert.equal(res.code, 0); // default --fail-on high, RDH902 is info
      const parsed = JSON.parse(res.out) as {
        findings: Array<{ ruleId: string; severity: string }>;
      };
      assert.equal(parsed.findings.length, 1);
      assert.equal(parsed.findings[0]?.ruleId, 'RDH902');
      assert.equal(parsed.findings[0]?.severity, 'info');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('produces valid SARIF 2.1.0 and supports --baseline suppression', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redos-hunter-sarif-'));
    try {
      const vulnFile = path.join(tmpDir, 'vuln.ts');
      fs.writeFileSync(vulnFile, 'export const r = /(a+)+$/;\n', 'utf8');

      // 1. Check exits 1 on high finding and emits valid SARIF 2.1.0
      const sarifRun = await captureCli(['check', tmpDir, '--format', 'sarif'], tmpDir);
      assert.equal(sarifRun.code, 1);

      const sarif = JSON.parse(sarifRun.out) as {
        version: string;
        runs: Array<{
          tool: { driver: { name: string; informationUri: string; rules: unknown[] } };
          results: Array<{
            ruleId: string;
            ruleIndex: number;
            level: string;
            partialFingerprints: { primaryLocationLineHash: string };
          }>;
        }>;
      };
      assert.equal(sarif.version, '2.1.0');
      assert.equal(sarif.runs[0]?.tool.driver.name, 'redos-hunter');
      assert.equal(sarif.runs[0]?.tool.driver.informationUri, EXPECTED_URI);
      assert.equal(sarif.runs[0]?.results.length, 1);
      assert.equal(sarif.runs[0]?.results[0]?.ruleId, 'RDH001');
      assert.equal(sarif.runs[0]?.results[0]?.level, 'error');
      assert.ok(sarif.runs[0]?.results[0]?.partialFingerprints.primaryLocationLineHash);

      // 2. Save SARIF as baseline and verify suppression yields exit code 0!
      const baselinePath = path.join(tmpDir, 'baseline.sarif.json');
      fs.writeFileSync(baselinePath, sarifRun.out, 'utf8');

      const suppressedRun = await captureCli(
        ['check', tmpDir, '--baseline', baselinePath, '--format', 'json'],
        tmpDir
      );
      assert.equal(suppressedRun.code, 0);
      const suppressedJson = JSON.parse(suppressedRun.out) as {
        summary: { suppressedCount: number; findingsCount: number };
      };
      assert.equal(suppressedJson.summary.suppressedCount, 1);
      assert.equal(suppressedJson.summary.findingsCount, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('supports explain subcommand and returns exit code 2 on invalid regex or bad CLI flags', async () => {
    const okExplain = await captureCli(['explain', '^(\\w+\\/?)+$', '--flags', 'gu'], REPO_ROOT);
    assert.equal(okExplain.code, 0);
    assert.ok(okExplain.out.includes('RDH005'));
    assert.ok(okExplain.out.includes('AST Outline:'));
    assert.ok(okExplain.out.includes('Rewrite:'));

    const badExplain = await captureCli(['explain', '([unclosed'], REPO_ROOT);
    assert.equal(badExplain.code, 2);

    const badLang = await captureCli(['check', '.', '--lang', 'cobol'], REPO_ROOT);
    assert.equal(badLang.code, 2);
  });

  it('enforces scan-root symlink/junction containment and supports symlinked CLI entrypoints', async () => {
    const outerTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'redos-hunter-sym-'));
    try {
      const scanRoot = path.join(outerTmp, 'workspace');
      const outsideDir = path.join(outerTmp, 'outside-secret');
      fs.mkdirSync(scanRoot);
      fs.mkdirSync(outsideDir);

      // Place a vulnerable file OUTSIDE scanRoot
      fs.writeFileSync(path.join(outsideDir, 'outside.js'), 'export const evil = /(a+)+$/;\n', 'utf8');
      // Place a clean file INSIDE scanRoot
      fs.writeFileSync(path.join(scanRoot, 'clean.js'), 'export const ok = /^[a-z]+$/;\n', 'utf8');

      // Create an escaping directory junction/symlink inside scanRoot -> outsideDir
      const escapeLink = path.join(scanRoot, 'escape-dir');
      fs.symlinkSync(
        outsideDir,
        escapeLink,
        process.platform === 'win32' ? 'junction' : 'dir'
      );

      // 1. Directory scan must NOT traverse escaping junction
      const dirRes = await captureCli(['check', scanRoot, '--format', 'json'], scanRoot);
      assert.equal(dirRes.code, 0);
      const parsed = JSON.parse(dirRes.out) as {
        summary: { scannedFilesCount: number; findingsCount: number };
      };
      assert.equal(parsed.summary.scannedFilesCount, 1);
      assert.equal(parsed.summary.findingsCount, 0);

      // 2. Explicitly passing escaping symlink relative to workspace cwd must exit 2 (SYMLINK_ESCAPE_BLOCKED)
      const directEscape = await captureCli(['check', 'escape-dir'], scanRoot);
      assert.equal(directEscape.code, 2);

      // 3. Symlinked CLI entrypoint test: invoke dist/cli.js through a symlinked/junction path
      const linkedDist = path.join(outerTmp, 'linked-dist');
      fs.symlinkSync(
        path.join(REPO_ROOT, 'dist'),
        linkedDist,
        process.platform === 'win32' ? 'junction' : 'dir'
      );
      let cliEntryToRun = path.join(linkedDist, 'cli.js');

      // Also create a direct file symlink if OS permissions allow (always on POSIX & GitHub Actions Windows)
      const directFileLink = path.join(outerTmp, 'redos-hunter-bin.js');
      try {
        fs.symlinkSync(DIST_CLI_PATH, directFileLink, 'file');
        cliEntryToRun = directFileLink;
      } catch {
        // Fallback to junctioned directory entrypoint on unprivileged Windows local accounts
      }

      assert.equal(isMainModule(pathToFileURL(DIST_CLI_PATH).href, cliEntryToRun), true);

      const stdout = execFileSync(process.execPath, [cliEntryToRun, '--version'], {
        shell: false,
        encoding: 'utf8'
      }).trim();
      assert.equal(stdout, '1.0.0');
    } finally {
      fs.rmSync(outerTmp, { recursive: true, force: true });
    }
  });
});
