import type {
  CheckReport,
  ExplainResult,
  OutputFormat,
  RedosFinding,
  RuleId,
  Severity
} from '../types.js';

export const PACKAGE_VERSION = '1.0.0';
export const INFORMATION_URI = 'https://github.com/pie527645-cloud/redos-hunter';

interface SarifRuleMetadata {
  id: RuleId;
  name: string;
  shortDescription: string;
  defaultLevel: 'error' | 'warning' | 'note';
}

const SARIF_RULES: readonly SarifRuleMetadata[] = [
  {
    id: 'RDH001',
    name: 'NestedAmbiguousQuantifier',
    shortDescription: 'Nested quantifier (star-height > 1) with cross-iteration overlap causes exponential backtracking.',
    defaultLevel: 'error'
  },
  {
    id: 'RDH002',
    name: 'OverlappingQuantifiedAlternation',
    shortDescription: 'Overlapping alternation branches inside a quantifier cause exponential backtracking.',
    defaultLevel: 'error'
  },
  {
    id: 'RDH003',
    name: 'AdjacentOverlappingQuantifiers',
    shortDescription: 'Adjacent overlapping quantifiers shift token boundaries polynomially.',
    defaultLevel: 'warning'
  },
  {
    id: 'RDH005',
    name: 'DelimiterAndTrailingSlashTrap',
    shortDescription: 'Nested optional delimiter loop or unanchored trailing quantifier causes catastrophic backtracking.',
    defaultLevel: 'error'
  },
  {
    id: 'RDH006',
    name: 'QuantifiedBackreference',
    shortDescription: 'Backreference inside a quantified group disables linear automaton execution.',
    defaultLevel: 'warning'
  },
  {
    id: 'RDH900',
    name: 'UnresolvableDynamicRegExp',
    shortDescription: 'Dynamic RegExp constructor argument could not be resolved statically.',
    defaultLevel: 'note'
  },
  {
    id: 'RDH901',
    name: 'PatternExceedsLengthCap',
    shortDescription: 'Regular expression exceeds maximum length cap (64 KB) and was skipped.',
    defaultLevel: 'note'
  },
  {
    id: 'RDH902',
    name: 'FileExceedsSizeCap',
    shortDescription: 'Source file exceeds maximum size cap (2 MB) and was skipped.',
    defaultLevel: 'note'
  },
  {
    id: 'RDH903',
    name: 'MaxPatternsCapReached',
    shortDescription: 'Maximum pattern count per run (10,000) reached.',
    defaultLevel: 'note'
  },
  {
    id: 'RDH904',
    name: 'InvalidRegExpSyntax',
    shortDescription: 'Extracted regular expression contains invalid syntax.',
    defaultLevel: 'note'
  }
];

function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

function stripTimingForNonJson(finding: RedosFinding): Omit<RedosFinding, 'evidence'> {
  const { evidence: _omitted, ...rest } = finding;
  void _omitted;
  return rest;
}

export function formatSarifReport(report: CheckReport): string {
  const ruleIndexMap = new Map<RuleId, number>();
  SARIF_RULES.forEach((r, idx) => ruleIndexMap.set(r.id, idx));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'redos-hunter',
            version: PACKAGE_VERSION,
            informationUri: INFORMATION_URI,
            rules: SARIF_RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.shortDescription },
              defaultConfiguration: { level: r.defaultLevel }
            }))
          }
        },
        results: report.findings.map((rawFinding) => {
          // Enforce spec invariant: timings NEVER appear in SARIF or fingerprints
          const f = stripTimingForNonJson(rawFinding);
          return {
            ruleId: f.ruleId,
            ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
            level: severityToSarifLevel(f.severity),
            message: {
              text: f.fix?.rewrite
                ? `${f.message} Suggested rewrite: /${f.fix.rewrite}/${f.fix.rewriteFlags ?? f.flags}`
                : f.message
            },
            partialFingerprints: {
              primaryLocationLineHash: f.fingerprint
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: f.file,
                    uriBaseId: '%SRCROOT%'
                  },
                  region: {
                    startLine: Math.max(1, f.line),
                    startColumn: Math.max(1, f.column)
                  }
                }
              }
            ],
            properties: {
              severity: f.severity,
              complexity: f.complexity,
              pattern: f.pattern,
              flags: f.flags,
              ...(f.attack ? { attackPreview: f.attack.preview } : {}),
              ...(f.fix?.rewrite ? { suggestedRewrite: f.fix.rewrite } : {})
            }
          };
        })
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatCheckReport(report: CheckReport, format: OutputFormat): string {
  if (format === 'sarif') {
    return formatSarifReport(report);
  }

  if (format === 'json') {
    return JSON.stringify(
      {
        summary: {
          scannedFilesCount: report.scannedFilesCount,
          extractedPatternsCount: report.extractedPatternsCount,
          suppressedCount: report.suppressedCount,
          findingsCount: report.findings.length
        },
        findings: report.findings
      },
      null,
      2
    );
  }

  if (format === 'markdown') {
    const lines: string[] = [
      '# redos-hunter Report',
      '',
      `- **Scanned Files:** ${report.scannedFilesCount}`,
      `- **Extracted Patterns:** ${report.extractedPatternsCount}`,
      `- **Suppressed (Baseline):** ${report.suppressedCount}`,
      `- **Total Findings:** ${report.findings.length}`,
      ''
    ];

    if (report.findings.length === 0) {
      lines.push('No ReDoS vulnerabilities or dynamic pattern warnings detected.');
      return lines.join('\n');
    }

    lines.push('| Severity | Rule | Class | Location | Pattern | Attack | Fix Hint |');
    lines.push('| --- | --- | --- | --- | --- | --- | --- |');
    for (const f of report.findings) {
      const esc = (s: string): string => s.replaceAll('|', '\\|').replaceAll('\n', ' ');
      const patDisplay = f.pattern ? `\`/${esc(f.pattern)}/${f.flags}\`` : '-';
      const atkDisplay = f.attack ? `\`${esc(f.attack.preview)}\`` : '-';
      const fixDisplay = f.fix
        ? f.fix.rewrite
          ? `\`/${esc(f.fix.rewrite)}/${f.fix.rewriteFlags ?? f.flags}\``
          : esc(f.fix.summary)
        : '-';
      lines.push(
        `| ${f.severity} | ${f.ruleId} | ${f.complexity} | ${esc(f.file)}:${f.line}:${f.column} | ${patDisplay} | ${atkDisplay} | ${fixDisplay} |`
      );
    }
    return lines.join('\n');
  }

  // Pretty format
  const lines: string[] = [
    `redos-hunter v${PACKAGE_VERSION} — scanned ${report.scannedFilesCount} file(s), ${report.extractedPatternsCount} pattern(s)` +
      (report.suppressedCount > 0 ? ` (${report.suppressedCount} suppressed by baseline)` : '')
  ];

  if (report.findings.length === 0) {
    lines.push('Clean: 0 findings.');
    return lines.join('\n');
  }

  lines.push(`Found ${report.findings.length} issue(s):`);
  lines.push('');

  for (const f of report.findings) {
    lines.push(
      `[${f.severity.toUpperCase()}] ${f.ruleId} (${f.complexity}) ${f.file}:${f.line}:${f.column}`
    );
    if (f.pattern) {
      lines.push(`  Pattern: /${f.pattern}/${f.flags}`);
    }
    lines.push(`  Detail:  ${f.message}`);
    if (f.overlapSummary) {
      lines.push(`  Overlap: ${f.overlapSummary}`);
    }
    if (f.attack) {
      lines.push(`  Attack:  ${f.attack.preview}`);
    }
    if (f.fix) {
      if (f.fix.rewrite !== null) {
        lines.push(`  Rewrite: /${f.fix.rewrite}/${f.fix.rewriteFlags ?? f.flags}`);
      }
      lines.push(`  Hint:    ${f.fix.summary}`);
    }
    if (f.evidence && f.evidence.status !== 'skipped') {
      lines.push(`  Confirm: ${f.evidence.status} (${f.evidence.backend})`);
    }
    lines.push('');
  }

  return lines.join('\n').trimEnd();
}

export function formatExplainReport(
  result: ExplainResult,
  format: 'pretty' | 'json' = 'pretty'
): string {
  if (format === 'json') {
    return JSON.stringify(result, null, 2);
  }

  const lines: string[] = [
    `Pattern: /${result.pattern}/${result.flags}`,
    '',
    'AST Outline:'
  ];

  for (const astLine of result.astSummary) {
    lines.push(`  ${astLine}`);
  }

  lines.push('');
  if (result.findings.length === 0) {
    lines.push('Analysis: Clean (0 static ReDoS findings).');
    return lines.join('\n');
  }

  lines.push(`Analysis: ${result.findings.length} static finding(s):`);
  for (const f of result.findings) {
    lines.push('');
    lines.push(`- [${f.severity.toUpperCase()}] ${f.ruleId} (class: ${f.complexity}, span: ${f.span.start}..${f.span.end})`);
    lines.push(`  Ambiguity: ${f.message}`);
    if (f.overlapSummary) {
      lines.push(`  Intervals: ${f.overlapSummary}`);
    }
    if (f.attack) {
      lines.push(`  Attack:    ${f.attack.preview}`);
    }
    if (f.fix) {
      if (f.fix.rewrite !== null) {
        lines.push(`  Rewrite:   /${f.fix.rewrite}/${f.fix.rewriteFlags ?? f.flags}`);
      }
      lines.push(`  Fix Hint:  ${f.fix.summary}`);
      if (f.fix.notes) {
        lines.push(`  Note:      ${f.fix.notes}`);
      }
    }
  }

  return lines.join('\n');
}
