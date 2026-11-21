import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  extractFromJsTs,
  extractFromSchemaContent,
  YamlSecurityError
} from '../src/index.js';

describe('JS/TS and JSON/YAML pattern extraction', () => {
  it('distinguishes /[/]/ regex literal from chained a / b / c division', () => {
    const code = [
      'const a = 100, b = 5, c = 2;',
      'const quotient = a / b / c;',
      'const slashChar = /[/]/g;',
      'const ratio = (a + b) / (c + 1) / 2;'
    ].join('\n');

    const res = extractFromJsTs(code, 'math.ts', 'ts');
    assert.equal(res.diagnostics.length, 0);
    assert.equal(res.patterns.length, 1);
    assert.equal(res.patterns[0]?.pattern, '[/]');
    assert.equal(res.patterns[0]?.flags, 'g');
    assert.equal(res.patterns[0]?.line, 3);
  });

  it('extracts regex literals inside JSX attributes', () => {
    const jsx = [
      'export function Form() {',
      '  return <TextField label="slug" validation={/^(\\w+\\/?)+$/} />;',
      '}'
    ].join('\n');

    const res = extractFromJsTs(jsx, 'Form.tsx', 'ts');
    assert.equal(res.patterns.length, 1);
    assert.equal(res.patterns[0]?.pattern, '^(\\w+\\/?)+$');
    assert.equal(res.patterns[0]?.line, 2);
  });

  it('resolves new RegExp(String.raw`...`) and same-file const strings while flagging dynamic RegExp as RDH900', () => {
    const code = [
      'const PREFIX = "^";',
      'const RAW = String.raw`(\\w+\\/?)+$`;',
      'const r1 = new RegExp(String.raw`^\\d+\\d+$`, "u");',
      'const r2 = new RegExp(PREFIX + RAW);',
      'function dynamicBuild(userInput: string) {',
      '  return new RegExp(userInput, "i");',
      '}'
    ].join('\n');

    const res = extractFromJsTs(code, 'constructors.ts', 'ts');
    assert.equal(res.patterns.length, 2);
    assert.equal(res.patterns[0]?.pattern, '^\\d+\\d+$');
    assert.equal(res.patterns[0]?.flags, 'u');
    assert.equal(res.patterns[1]?.pattern, '^(\\w+\\/?)+$');

    assert.equal(res.diagnostics.length, 1);
    assert.equal(res.diagnostics[0]?.ruleId, 'RDH900');
    assert.equal(res.diagnostics[0]?.line, 6);
  });

  it('emits RDH901 info diagnostic when pattern exceeds 64 KB cap', () => {
    const huge = 'a'.repeat(66_000);
    const code = `const r = /${huge}/;`;
    const res = extractFromJsTs(code, 'huge.js', 'js');
    assert.equal(res.patterns.length, 0);
    assert.equal(res.diagnostics.length, 1);
    assert.equal(res.diagnostics[0]?.ruleId, 'RDH901');
  });

  it('preserves exact 1-based line and column offsets on CRLF files', () => {
    const crlfCode = 'const x = 1;\r\nconst y = 2;\r\n  const bad = /(a+)+$/;\r\n';
    const res = extractFromJsTs(crlfCode, 'crlf.ts', 'ts');
    assert.equal(res.patterns.length, 1);
    assert.equal(res.patterns[0]?.line, 3);
    assert.equal(res.patterns[0]?.column, 15);
  });

  it('extracts pattern and patternProperties from JSON Schema / OpenAPI / MCP inputSchema without false positives on property names', () => {
    const mcpSchemaJson = JSON.stringify(
      {
        tools: [
          {
            name: 'search',
            inputSchema: {
              type: 'object',
              properties: {
                // Property named "pattern" must NOT treat its subschema object as a regex
                pattern: {
                  type: 'string',
                  pattern: '^[a-z0-9-]+$',
                  example: { pattern: '(a+)+$' }
                }
              },
              patternProperties: {
                '^(\\w+\\/?)+$': { type: 'string' }
              }
            }
          }
        ]
      },
      null,
      2
    );

    const res = extractFromSchemaContent(mcpSchemaJson, 'mcp.json', 'json');
    assert.equal(res.patterns.length, 2);
    assert.equal(res.patterns[0]?.pattern, '^[a-z0-9-]+$');
    assert.equal(res.patterns[0]?.origin, 'schema-pattern');
    assert.equal(res.patterns[1]?.pattern, '^(\\w+\\/?)+$');
    assert.equal(res.patterns[1]?.origin, 'schema-pattern-property');
  });

  it('enforces maxAliasCount cap on YAML billion-laughs payloads', () => {
    const yamlBomb = [
      'a: &a ["x", "x", "x", "x"]',
      'b: &b [*a, *a, *a, *a]',
      'c: &c [*b, *b, *b, *b]',
      'd: &d [*c, *c, *c, *c]',
      'e: &e [*d, *d, *d, *d]'
    ].join('\n');

    assert.throws(
      () => extractFromSchemaContent(yamlBomb, 'bomb.yaml', 'yaml', { maxAliasCount: 25 }),
      YamlSecurityError
    );
  });
});
