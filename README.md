# @pie527645-cloud/redos-hunter

Static regular expression ambiguity analyzer and isolated sandbox empirical ReDoS confirmation CLI for JavaScript, TypeScript, JSON Schema, OpenAPI, and Model Context Protocol (`inputSchema`) definitions.

## Why `redos-hunter`?

- **Beyond naive star-height checks:** Tools such as `safe-regex` inspect syntactic star height alone, producing high false-positive rates on disjoint delimiter loops (`^\w+(?:\/\w+)*\/?$`) while missing polynomial $O(n^2) / O(n^3)$ traps (`/^\/+|\/+$/g`, `\d+\d+`, `.*.*=`).
- **Flag-accurate code-point interval set math:** Character classes, escapes (`\w`, `\d`, `\s`, `\p{...}`), case-folding (`i`), Unicode code points (`u`), and ECMAScript 2024 `v`-flag set subtraction/intersection (`[[a-z]--[m-p]]`) are evaluated as exact sorted closed intervals.
- **Actionable attack strings and verified rewrites:** Every static finding includes a deterministic pump/suffix witness string and a concrete linear rewrite verified to pass `RDH001`–`RDH006`.
- **Isolated empirical `--confirm`:** Optionally verifies super-linear growth (`exp` or `poly`) inside an isolated sandbox (`worker_threads` or `child_process` with `shell: false` and empty `env`) under strict per-probe timeouts without ever executing scanned repository code.

## Requirements

- Node.js `>=20.18.1`

## Installation

```bash
npm install -D @pie527645-cloud/redos-hunter
```

Or run directly via `npx`:

```bash
npx @pie527645-cloud/redos-hunter check .
```

## CLI Usage

### `redos-hunter check`

Scan files or directories for catastrophic backtracking vulnerabilities:

```bash
redos-hunter check [paths..] \
  [--lang js,ts,json,yaml] \
  [--confirm] \
  [--timeout-ms 250] \
  [--format pretty|json|markdown|sarif] \
  [--fail-on info|low|medium|high] \
  [--baseline <file>]
```

Options:
- `--lang <list>`: Comma-separated languages to scan (`js,ts,json,yaml`, default: all four).
- `--confirm`: Run deterministic pump inputs inside an isolated sandbox (`n = 8,12,16,20,24` for `exp`; `n = 1000,2000,4000,8000` for `poly`). Empirical timing is emitted **only** in `--format json` under `evidence` (never in SARIF or fingerprints) and never downgrades static findings.
- `--timeout-ms <ms>`: Per-probe timeout budget in milliseconds when `--confirm` is enabled (default: `250`).
- `--format <fmt>`: Output format: `pretty` (default), `json`, `markdown`, or `sarif` (SARIF 2.1.0).
- `--fail-on <severity>`: Minimum severity that triggers exit code `1` (`info`, `low`, `medium`, or `high`; default: `high`).
- `--baseline <file>`: Suppress known findings matching deterministic fingerprints from a previous JSON report, fingerprint array, or SARIF 2.1.0 log.

### `redos-hunter explain`

Inspect a single pattern's AST, overlapping code-point intervals, witness attack string, and rewrite hint:

```bash
redos-hunter explain "^(\w+\/?)+$" --flags gu
redos-hunter explain "([[a-z]--[m-p]]|[m-p])+$" --flags v --format json
```

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Clean (no active findings at or above `--fail-on`) |
| `1` | One or more active findings at or above `--fail-on` |
| `2` | CLI usage error, unreadable target, symlink escape, invalid JSON/YAML, or YAML alias bomb |

## Rule Reference (v1)

| Rule | Severity | Class | Description | Example | Linear Rewrite |
| --- | --- | --- | --- | --- | --- |
| `RDH001` | `high` | `exp` | Nested quantifier (`star-height > 1`) with cross-iteration overlap | `^(a+)+$`, `^(\w+\s?)*$` | `^a+$`, `^(?:\w+(?:\s\|$))*$` |
| `RDH002` | `high` | `exp` | Overlapping alternation branches under a quantifier | `^(\w\|\d)+$`, `(.|\s)*$` | `^\w+$`, `[\s\S]*$` |
| `RDH003` | `medium` / `high` | `poly` | Adjacent overlapping quantifiers shifting token boundaries quadratically | `^\d+\d+$`, `.*.*=` | `^\d{2,}$`, `[^=\r\n]*=` |
| `RDH005` | `high` | `exp` / `poly` | Nested optional slash/delimiter trap or unanchored trailing quantifier | `^(\w+\/?)+$`, `/^\/+\|\/+$/g` | `^\w+(?:\/\w+)*\/?$`, two-pointer `trimSlashes` / `^\/+\|(?<!\/)\/+$` |
| `RDH006` | `medium` | `warning` | Backreference inside a quantified group (excluding atomic `(?=(...))\1` emulation) | `^(([a-z])\2)+$` | Validate repeated equality in code |
| `RDH900` | `info` | `info` | Unresolvable dynamic `new RegExp(...)` argument | `new RegExp(input)` | Validate or escape untrusted input |
| `RDH901` | `info` | `info` | Pattern exceeds `64 KB` cap and was skipped | — | Reduce generated pattern size |
| `RDH902` | `info` | `info` | File exceeds `2 MB` size cap and was skipped | — | Exclude minified bundles |
| `RDH903` | `info` | `info` | Run reached `10,000` extracted patterns cap | — | Scope scan targets |
| `RDH904` | `low` | `info` | Extracted regular expression has invalid syntax | `([unclosed` | Fix regular expression syntax |

## Extraction Coverage

- **JavaScript & TypeScript (`.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`):**
  - Uses the official `typescript` parser/scanner so regex literals (`/[/]/g`) vs chained division (`a / b / c`) and JSX attribute expressions (`<Input pattern={/.../} />`) are lexed accurately.
  - Resolves `new RegExp(...)` and `RegExp(...)` over string literals, no-substitution templates, `String.raw\`...\``, binary `+` string concatenations, and lexical same-file `const` string bindings.
  - Emits `RDH900` (`info`) for dynamic runtime arguments rather than silently skipping them.
- **JSON & YAML Schemas (`.json`, `.yaml`, `.yml`):**
  - Extracts `pattern` strings and `patternProperties` keys across JSON Schema, OpenAPI 3.x, and MCP tool `inputSchema` definitions while ignoring `example`, `examples`, `default`, `const`, and `enum` payloads.
  - Enforces `maxAliasCount` (`100`) on YAML documents to block billion-laughs alias expansion attacks.

## Common Linear Rewrites

1. **Trimming leading/trailing slashes (`RDH005`):**
   Unanchored `/^\/+|\/+$/g` scans from every character offset in interior slash runs (`O(n^2)`). Prefer a linear two-pointer slice helper:
   ```ts
   export function trimSlashes(input: string): string {
     let start = 0;
     let end = input.length;
     while (start < end && input.charCodeAt(start) === 47) start++;
     while (end > start && input.charCodeAt(end - 1) === 47) end--;
     return start === 0 && end === input.length ? input : input.slice(start, end);
   }
   ```
   Or guard the trailing branch with a negative lookbehind: `/^\/+|(?<!\/)\/+$/g`.
2. **Optional path delimiters (`RDH005`):**
   Rewrite `/^(\w+\/?)+$/` to `/^\w+(?:\/\w+)*\/?$/` so `/` is required between `\w+` segments.
3. **Disjoint sets with `v` flag (`RDH002`):**
   Use Unicode Sets subtraction: `/^([[a-z]--[m-p]]|[m-p])+$/v`.
4. **Possessive / atomic emulation (`RDH001`):**
   Use positive lookahead capture + backreference `(?=(a+))\1` so V8 commits to the greedy match. As a runtime last resort when lookarounds and backreferences are not needed, Node.js offers `--enable-experimental-regexp-engine` (`/l` flag).

## Security Invariants

- **Zero code execution:** Scanned source files and schemas are parsed strictly as data/ASTs and are never imported, required, or evaluated.
- **Sandbox isolation:** Patterns are compiled only inside the isolated sandbox worker/child over `{ source, flags, input }` messages with an empty environment (`env: {}`), `shell: false`, and hard timeout termination.
- **Realpath containment:** Scan traversal resolves `realpathSync.native` and refuses to follow symbolic links or Windows directory junctions escaping the scan root.
- **Zero network:** Operates completely offline.

## Programmatic API

```ts
import { analyzePattern, explainPattern, runWorkspaceCheck } from '@pie527645-cloud/redos-hunter';

const findings = analyzePattern('^(\\w+\\/?)+$', 'u');
console.log(findings[0]?.ruleId, findings[0]?.fix?.rewrite);
// -> RDH005  ^\w+(?:\/\w+)*\/?$

const report = await runWorkspaceCheck({
  paths: ['./src'],
  confirm: true,
  timeoutMs: 250
});
console.log(report.findings.length);
```

## License

MIT
