import * as path from 'node:path';
import ts from 'typescript';
import { MAX_PATTERN_LENGTH } from '../security/pathGuard.js';
import type {
  ExtractedPattern,
  ExtractionDiagnostic,
  SupportedLanguage
} from '../types.js';

export interface ExtractionResult {
  patterns: ExtractedPattern[];
  diagnostics: ExtractionDiagnostic[];
}

interface Scope {
  parent: Scope | null;
  consts: Map<string, string | null>;
  shadowedNonConst: Set<string>;
}

function getScriptKind(filePath: string, language: SupportedLanguage): ts.ScriptKind {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.tsx') {
    return ts.ScriptKind.TSX;
  }
  if (ext === '.jsx') {
    return ts.ScriptKind.JSX;
  }
  if (ext === '.ts' || ext === '.mts' || ext === '.cts') {
    return ts.ScriptKind.TS;
  }
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    // ScriptKind.JSX parses all valid JS syntax plus JSX elements/attributes
    return ts.ScriptKind.JSX;
  }
  return language === 'ts' ? ts.ScriptKind.TS : ts.ScriptKind.JSX;
}

function lookupConstString(scope: Scope, name: string): string | null | undefined {
  let cur: Scope | null = scope;
  while (cur) {
    if (cur.shadowedNonConst.has(name)) {
      return null;
    }
    if (cur.consts.has(name)) {
      return cur.consts.get(name) ?? null;
    }
    cur = cur.parent;
  }
  return undefined;
}

function isRegExpGlobalShadowed(scope: Scope): boolean {
  let cur: Scope | null = scope;
  while (cur) {
    if (cur.consts.has('RegExp') || cur.shadowedNonConst.has('RegExp')) {
      return true;
    }
    cur = cur.parent;
  }
  return false;
}

function isStringRawTag(expr: ts.Expression): boolean {
  if (
    ts.isPropertyAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === 'String' &&
    expr.name.text === 'raw'
  ) {
    return true;
  }
  return false;
}

function resolveStaticString(
  expr: ts.Expression,
  scope: Scope,
  depth = 0
): string | null {
  if (depth > 16) {
    return null;
  }
  if (ts.isParenthesizedExpression(expr)) {
    return resolveStaticString(expr.expression, scope, depth + 1);
  }
  if (ts.isAsExpression(expr) || ts.isSatisfiesExpression(expr)) {
    return resolveStaticString(expr.expression, scope, depth + 1);
  }
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return expr.text;
  }
  if (ts.isTemplateExpression(expr)) {
    let out = expr.head.text;
    for (const span of expr.templateSpans) {
      const sub = resolveStaticString(span.expression, scope, depth + 1);
      if (sub === null) {
        return null;
      }
      out += sub + span.literal.text;
    }
    return out;
  }
  if (ts.isTaggedTemplateExpression(expr) && isStringRawTag(expr.tag)) {
    const tmpl = expr.template;
    if (ts.isNoSubstitutionTemplateLiteral(tmpl)) {
      return tmpl.rawText ?? tmpl.text;
    }
    if (ts.isTemplateExpression(tmpl)) {
      let out = tmpl.head.rawText ?? tmpl.head.text;
      for (const span of tmpl.templateSpans) {
        const sub = resolveStaticString(span.expression, scope, depth + 1);
        if (sub === null) {
          return null;
        }
        out += sub + (span.literal.rawText ?? span.literal.text);
      }
      return out;
    }
  }
  if (ts.isIdentifier(expr)) {
    const found = lookupConstString(scope, expr.text);
    return typeof found === 'string' ? found : null;
  }
  if (
    ts.isBinaryExpression(expr) &&
    expr.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = resolveStaticString(expr.left, scope, depth + 1);
    if (left === null) {
      return null;
    }
    const right = resolveStaticString(expr.right, scope, depth + 1);
    if (right === null) {
      return null;
    }
    return left + right;
  }
  return null;
}

function parseRegexLiteralText(rawText: string): { pattern: string; flags: string } | null {
  if (rawText.length < 2 || rawText.charCodeAt(0) !== 0x2f /* '/' */) {
    return null;
  }
  const lastSlash = rawText.lastIndexOf('/');
  if (lastSlash <= 0) {
    return null;
  }
  return {
    pattern: rawText.slice(1, lastSlash),
    flags: rawText.slice(lastSlash + 1)
  };
}

function isRegExpConstructorCallee(expr: ts.Expression, scope: Scope): boolean {
  if (ts.isParenthesizedExpression(expr)) {
    return isRegExpConstructorCallee(expr.expression, scope);
  }
  if (ts.isIdentifier(expr) && expr.text === 'RegExp') {
    return !isRegExpGlobalShadowed(scope);
  }
  if (
    ts.isPropertyAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    (expr.expression.text === 'globalThis' || expr.expression.text === 'window') &&
    expr.name.text === 'RegExp'
  ) {
    return true;
  }
  return false;
}

function createsNewScope(node: ts.Node): boolean {
  return (
    ts.isBlock(node) ||
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isForStatement(node) ||
    ts.isForInStatement(node) ||
    ts.isForOfStatement(node) ||
    ts.isCaseBlock(node) ||
    ts.isCatchClause(node) ||
    ts.isModuleBlock(node)
  );
}

function populateScopeDeclarations(container: ts.Node, scope: Scope): void {
  const statements: readonly ts.Statement[] | undefined = ts.isSourceFile(container)
    ? container.statements
    : ts.isBlock(container) || ts.isModuleBlock(container)
      ? container.statements
      : undefined;

  if (!statements) {
    return;
  }

  for (const stmt of statements) {
    if (!ts.isVariableStatement(stmt)) {
      continue;
    }
    const declList = stmt.declarationList;
    const isConst = (declList.flags & ts.NodeFlags.Const) !== 0;
    for (const decl of declList.declarations) {
      if (!ts.isIdentifier(decl.name)) {
        continue;
      }
      const varName = decl.name.text;
      if (isConst && decl.initializer) {
        const val = resolveStaticString(decl.initializer, scope);
        if (val !== null && val.length <= MAX_PATTERN_LENGTH * 2) {
          scope.consts.set(varName, val);
        } else {
          scope.consts.set(varName, null);
        }
      } else {
        scope.shadowedNonConst.add(varName);
      }
    }
  }
}

export function extractFromJsTs(
  content: string,
  displayFilePath: string,
  language: 'js' | 'ts',
  maxPatternLength = MAX_PATTERN_LENGTH
): ExtractionResult {
  const scriptKind = getScriptKind(displayFilePath, language);
  const sourceFile = ts.createSourceFile(
    displayFilePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind
  );

  const patterns: ExtractedPattern[] = [];
  const diagnostics: ExtractionDiagnostic[] = [];

  const rootScope: Scope = {
    parent: null,
    consts: new Map(),
    shadowedNonConst: new Set()
  };
  populateScopeDeclarations(sourceFile, rootScope);

  function getLineCol(node: ts.Node): { line: number; column: number } {
    const pos = node.getStart(sourceFile);
    const lc = sourceFile.getLineAndCharacterOfPosition(pos);
    return { line: lc.line + 1, column: lc.character + 1 };
  }

  function recordPattern(
    pattern: string,
    flags: string,
    node: ts.Node,
    origin: 'regex-literal' | 'regexp-constructor'
  ): void {
    const { line, column } = getLineCol(node);
    if (pattern.length > maxPatternLength) {
      diagnostics.push({
        ruleId: 'RDH901',
        message: `Regular expression pattern length (${pattern.length} chars) exceeds ${maxPatternLength} limit and was skipped.`,
        file: displayFilePath,
        line,
        column,
        flags
      });
      return;
    }
    patterns.push({
      pattern,
      flags,
      file: displayFilePath,
      line,
      column,
      language,
      origin
    });
  }

  function visit(node: ts.Node, currentScope: Scope): void {
    let activeScope = currentScope;
    if (createsNewScope(node)) {
      activeScope = {
        parent: currentScope,
        consts: new Map(),
        shadowedNonConst: new Set()
      };
      if (
        ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isConstructorDeclaration(node)
      ) {
        for (const param of node.parameters) {
          if (ts.isIdentifier(param.name)) {
            activeScope.shadowedNonConst.add(param.name.text);
          }
        }
      }
      populateScopeDeclarations(node, activeScope);
    }

    if (ts.isRegularExpressionLiteral(node)) {
      // Skip if this literal is the direct first argument of RegExp(...) / new RegExp(...) to avoid double-counting
      const parent = node.parent;
      const isDirectRegExpArg =
        parent &&
        (ts.isNewExpression(parent) || ts.isCallExpression(parent)) &&
        parent.arguments?.[0] === node &&
        isRegExpConstructorCallee(parent.expression, activeScope);

      if (!isDirectRegExpArg) {
        const parsed = parseRegexLiteralText(node.text);
        if (parsed) {
          recordPattern(parsed.pattern, parsed.flags, node, 'regex-literal');
        }
      }
    } else if (
      (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
      isRegExpConstructorCallee(node.expression, activeScope)
    ) {
      const args = node.arguments;
      if (!args || args.length === 0) {
        // new RegExp() with 0 args matches (?:) which is trivially safe; skip
      } else {
        const patArg = args[0]!;
        const flagsArg = args[1];

        let resolvedPattern: string | null = null;
        let defaultFlags = '';

        if (ts.isRegularExpressionLiteral(patArg)) {
          const parsed = parseRegexLiteralText(patArg.text);
          if (parsed) {
            resolvedPattern = parsed.pattern;
            defaultFlags = parsed.flags;
          }
        } else {
          resolvedPattern = resolveStaticString(patArg, activeScope);
        }

        let resolvedFlags: string | null = defaultFlags;
        if (flagsArg !== undefined) {
          if (ts.isIdentifier(flagsArg) && flagsArg.text === 'undefined') {
            resolvedFlags = defaultFlags;
          } else {
            resolvedFlags = resolveStaticString(flagsArg, activeScope);
          }
        }

        if (resolvedPattern === null || resolvedFlags === null) {
          const { line, column } = getLineCol(node);
          diagnostics.push({
            ruleId: 'RDH900',
            message:
              'Unresolvable dynamic RegExp constructor argument; static ReDoS analysis could not inspect runtime pattern.',
            file: displayFilePath,
            line,
            column
          });
        } else {
          recordPattern(resolvedPattern, resolvedFlags, node, 'regexp-constructor');
        }
      }
    }

    ts.forEachChild(node, (child) => visit(child, activeScope));
  }

  visit(sourceFile, rootScope);
  return { patterns, diagnostics };
}
