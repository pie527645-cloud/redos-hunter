import {
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  LineCounter,
  parseAllDocuments,
  type Node as YamlNode
} from 'yaml';
import {
  MAX_PATTERN_LENGTH,
  MAX_YAML_ALIASES,
  UsageError,
  YamlSecurityError
} from '../security/pathGuard.js';
import type { ExtractedPattern } from '../types.js';
import type { ExtractionResult } from './jsExtractor.js';

const NON_SCHEMA_VALUE_CONTAINERS = new Set<string>([
  'example',
  'examples',
  'default',
  'const',
  'enum'
]);

export function extractFromSchemaContent(
  content: string,
  displayFilePath: string,
  language: 'json' | 'yaml',
  options: { maxPatternLength?: number; maxAliasCount?: number } = {}
): ExtractionResult {
  const maxPatternLength = options.maxPatternLength ?? MAX_PATTERN_LENGTH;
  const maxAliasCount = options.maxAliasCount ?? MAX_YAML_ALIASES;

  if (language === 'json') {
    try {
      JSON.parse(content);
    } catch (err) {
      throw new UsageError(
        `Invalid JSON in ${displayFilePath}: ${err instanceof Error ? err.message : String(err)}`,
        'INVALID_JSON'
      );
    }
  }

  const lineCounter = new LineCounter();
  const docs = parseAllDocuments(content, {
    lineCounter,
    prettyErrors: false
  });

  const patterns: ExtractedPattern[] = [];
  const diagnostics: ExtractionResult['diagnostics'] = [];

  for (const doc of docs) {
    if (doc.errors.length > 0) {
      const firstErr = doc.errors[0]!;
      throw new UsageError(
        `Invalid ${language.toUpperCase()} in ${displayFilePath}: ${firstErr.message}`,
        'INVALID_SCHEMA_SYNTAX'
      );
    }

    // Enforce billion-laughs alias expansion cap using yaml's maxAliasCount check
    try {
      doc.toJS({ maxAliasCount });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.toLowerCase().includes('alias')) {
        throw new YamlSecurityError(
          `YAML alias expansion in ${displayFilePath} exceeds maxAliasCount (${maxAliasCount}).`,
          'YAML_ALIAS_LIMIT'
        );
      }
      throw new UsageError(
        `Failed to materialize ${language.toUpperCase()} document ${displayFilePath}: ${msg}`,
        'YAML_PARSE_ERROR'
      );
    }

    let expandedAliases = 0;
    const activeAnchors = new Set<YamlNode>();

    function getOffsetLineCol(offset: number | undefined): { line: number; column: number } {
      if (offset === undefined || offset < 0) {
        return { line: 1, column: 1 };
      }
      const pos = lineCounter.linePos(offset);
      return { line: pos.line, column: pos.col };
    }

    function recordSchemaPattern(
      patternText: string,
      offset: number | undefined,
      origin: 'schema-pattern' | 'schema-pattern-property'
    ): void {
      const { line, column } = getOffsetLineCol(offset);
      if (patternText.length > maxPatternLength) {
        diagnostics.push({
          ruleId: 'RDH901',
          message: `Schema pattern length (${patternText.length} chars) exceeds ${maxPatternLength} limit and was skipped.`,
          file: displayFilePath,
          line,
          column,
          flags: ''
        });
        return;
      }
      patterns.push({
        pattern: patternText,
        flags: '',
        file: displayFilePath,
        line,
        column,
        language,
        origin
      });
    }

    function walkNode(node: unknown, parentMapKey: string | null): void {
      if (!node || typeof node !== 'object') {
        return;
      }

      if (isAlias(node)) {
        expandedAliases++;
        if (expandedAliases > maxAliasCount) {
          throw new YamlSecurityError(
            `YAML alias expansion in ${displayFilePath} exceeds maxAliasCount (${maxAliasCount}).`,
            'YAML_ALIAS_LIMIT'
          );
        }
        const resolved = node.resolve(doc);
        if (resolved && !activeAnchors.has(resolved)) {
          activeAnchors.add(resolved);
          walkNode(resolved, parentMapKey);
          activeAnchors.delete(resolved);
        }
        return;
      }

      if (isSeq(node)) {
        for (const item of node.items) {
          walkNode(item, null);
        }
        return;
      }

      if (isMap(node)) {
        // Check if this map itself is the value of `patternProperties`
        // (and not a named property inside `properties: { patternProperties: { type: ... } }`)
        if (parentMapKey === 'patternProperties') {
          for (const pair of node.items) {
            if (!isPair(pair)) {
              continue;
            }
            const keyNode = pair.key;
            const valNode = pair.value;
            if (isScalar(keyNode) && typeof keyNode.value === 'string') {
              // In JSON Schema, patternProperties maps regex strings to subschema objects or booleans
              const isSubschema =
                isMap(valNode) ||
                isAlias(valNode) ||
                (isScalar(valNode) && typeof valNode.value === 'boolean');
              if (isSubschema) {
                recordSchemaPattern(
                  keyNode.value,
                  keyNode.range?.[0],
                  'schema-pattern-property'
                );
              }
            }
            walkNode(valNode, null);
          }
          return;
        }

        // If this map is `properties`, `$defs`, `definitions`, `schemas`, `responses`, etc.,
        // its direct keys are user-defined identifiers, NOT JSON Schema keywords!
        const keysAreArbitraryNames =
          parentMapKey === 'properties' ||
          parentMapKey === '$defs' ||
          parentMapKey === 'definitions' ||
          parentMapKey === 'dependentSchemas' ||
          parentMapKey === 'dependencies';

        for (const pair of node.items) {
          if (!isPair(pair)) {
            continue;
          }
          const keyNode = pair.key;
          const valNode = pair.value;
          const keyStr =
            isScalar(keyNode) && typeof keyNode.value === 'string' ? keyNode.value : null;

          if (!keysAreArbitraryNames && keyStr !== null) {
            if (NON_SCHEMA_VALUE_CONTAINERS.has(keyStr)) {
              continue;
            }
            if (keyStr === 'pattern' && isScalar(valNode) && typeof valNode.value === 'string') {
              recordSchemaPattern(valNode.value, valNode.range?.[0], 'schema-pattern');
              continue;
            }
          }

          walkNode(valNode, keysAreArbitraryNames ? null : keyStr);
        }
      }
    }

    if (doc.contents) {
      walkNode(doc.contents, null);
    }
  }

  return { patterns, diagnostics };
}
