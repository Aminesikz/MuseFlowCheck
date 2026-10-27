#!/usr/bin/env node
// CLI entrypoint: `flowcheck scan <file>` — exit 0 clean, 1 high/critical finding, 2 usage/runtime error.
import { analyzeFile, FindingParseError } from "./engine/index.js";
import { describeApiError, loadDotEnv } from "./llm/errors.js";
import type { Finding } from "./types/index.js";

const VERSION = "0.0.0";
const USAGE = `flowcheck v${VERSION}

Usage:
  flowcheck scan <file>   Scan one JS/TS file for SQL injection
  flowcheck --version

Exit codes: 0 no high/critical findings, 1 high/critical finding(s), 2 error`;

const EXIT_GATE = 1;
const EXIT_ERROR = 2;

function indent(text: string, prefix = "    "): string {
  return text
    .split("\n")
    .map((line) => prefix + line)
    .join("\n");
}

function formatFinding(f: Finding, n: number): string {
  return [
    `[${n}] ${f.type} — ${f.severity.toUpperCase()} — ${f.cwe} (${f.confidence})`,
    `  Source: ${f.file}:${f.sourceLine}`,
    `  Sink:   ${f.file}:${f.sinkLine}`,
    `  Taint path:`,
    ...f.taintPath.map((hop) => `    → ${hop}`),
    `  Why it's exploitable:`,
    indent(f.explanation),
    `  Suggested patch:`,
    indent(f.suggestedPatch),
  ].join("\n");
}

async function scan(file: string): Promise<number> {
  loadDotEnv();
  console.log(`Scanning ${file} for SQL injection...\n`);

  let findings: Finding[];
  try {
    findings = await analyzeFile(file);
  } catch (err) {
    if (err instanceof FindingParseError) {
      console.error(`✗ Could not parse model response: ${err.message}\n\n--- raw model response ---\n${err.raw}\n--- end ---`);
    } else if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      console.error(`✗ File not found: ${file}`);
    } else {
      console.error(`✗ ${describeApiError(err)}`);
    }
    return EXIT_ERROR;
  }

  findings.forEach((f, i) => console.log(formatFinding(f, i + 1) + "\n"));

  const gated = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  console.log(`Summary: ${findings.length} finding(s), ${gated} high/critical.`);
  return gated > 0 ? EXIT_GATE : 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === "--version" || command === "-v") {
    console.log(`flowcheck v${VERSION}`);
    return 0;
  }
  if (command === "scan" && rest.length === 1) return scan(rest[0]);
  if (command === undefined || command === "--help" || command === "-h") {
    console.log(USAGE);
    return 0;
  }
  console.error(USAGE);
  return EXIT_ERROR;
}

main(process.argv.slice(2)).then((code) => process.exit(code));
