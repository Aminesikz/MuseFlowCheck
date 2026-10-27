#!/usr/bin/env node
// CLI entrypoint: `flowcheck scan` / `flowcheck trace` — exit 0 clean, 1 high/critical finding, 2 usage/runtime error.
import { analyzeFile, FindingParseError } from "./engine/index.js";
import { buildJudgePrompt, formatHop, groupBySink, judgeTrace, traceEntry, type TraceResult } from "./engine/crossfile/index.js";
import { describeApiError, loadDotEnv } from "./llm/errors.js";
import type { Finding } from "./types/index.js";

const VERSION = "0.0.0";
const USAGE = `flowcheck v${VERSION}

Usage:
  flowcheck scan <file>                              Scan one JS/TS file for SQL injection (single-file)
  flowcheck scan <entry> --cross-file [--root <dir>] Trace request input from <entry> across files, then judge with the model
  flowcheck trace <entry> [--root <dir>] [--show-prompt]
                                                     Stage 1 only: print traced paths (no API call);
                                                     --show-prompt also prints the Stage 2 prompt(s)
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
    `  Sink:   ${f.sinkFile ?? f.file}:${f.sinkLine}`,
    `  Taint path:`,
    ...f.taintPath.map((hop) => `    → ${hop}`),
    `  Why it's exploitable:`,
    indent(f.explanation),
    `  Suggested patch:`,
    indent(f.suggestedPatch),
  ].join("\n");
}

function formatTrace(trace: TraceResult): string {
  const sqlText = trace.paths.filter((p) => p.sqlText);
  const bound = trace.paths.filter((p) => !p.sqlText);
  const out = [
    `Stage 1 — trace from ${trace.entry} (root: ${trace.root})`,
    `  Request handlers found: ${trace.handlers}`,
    "",
    `Candidate paths into SQL text: ${sqlText.length}`,
  ];
  sqlText.forEach((p, i) => {
    out.push(`  Path ${i + 1}:`);
    for (const h of p.hops) out.push(`    [${h.kind.padEnd(9)}] ${formatHop(h)}`);
  });
  out.push("", `Paths reaching SQL only as bound parameters (not sent to the model): ${bound.length}`);
  for (const p of bound) out.push(`  ${formatHop(p.hops[0])}\n    ⤷ ${formatHop(p.hops.at(-1)!)}`);
  out.push("", `Unresolved calls (where a trace broke): ${trace.unresolved.length || "none"}`);
  for (const u of trace.unresolved) out.push(`  ${u.file}:${u.line}  ${u.call} — ${u.reason}`);
  return out.join("\n");
}

function reportError(err: unknown, file: string): number {
  if (err instanceof FindingParseError) {
    console.error(`✗ Could not parse model response: ${err.message}\n\n--- raw model response ---\n${err.raw}\n--- end ---`);
  } else if ((err as NodeJS.ErrnoException).code === "ENOENT") {
    console.error(`✗ File not found: ${file}`);
  } else {
    console.error(`✗ ${describeApiError(err)}`);
  }
  return EXIT_ERROR;
}

function printFindings(findings: Finding[]): number {
  findings.forEach((f, i) => console.log(formatFinding(f, i + 1) + "\n"));
  const gated = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  console.log(`Summary: ${findings.length} finding(s), ${gated} high/critical.`);
  return gated > 0 ? EXIT_GATE : 0;
}

async function scan(file: string): Promise<number> {
  loadDotEnv();
  console.log(`Scanning ${file} for SQL injection...\n`);
  try {
    return printFindings(await analyzeFile(file));
  } catch (err) {
    return reportError(err, file);
  }
}

async function scanCrossFile(entry: string, root?: string): Promise<number> {
  loadDotEnv();
  console.log(`Cross-file scan of ${entry} for SQL injection...\n`);
  let trace: TraceResult;
  try {
    trace = traceEntry(entry, root);
  } catch (err) {
    return reportError(err, entry);
  }
  console.log(formatTrace(trace) + "\n");

  const groups = groupBySink(trace.paths);
  if (groups.length === 0) {
    console.log("Stage 1 found no candidate path into SQL text — nothing sent to the model (no single-file fallback).");
    return 0;
  }
  console.log(`Stage 2 — asking the model to judge ${groups.length} SQL execution call(s)...\n`);
  try {
    return printFindings(await judgeTrace(trace));
  } catch (err) {
    return reportError(err, entry);
  }
}

function trace(entry: string, root: string | undefined, showPrompt: boolean): number {
  let result: TraceResult;
  try {
    result = traceEntry(entry, root);
  } catch (err) {
    return reportError(err, entry);
  }
  console.log(formatTrace(result));
  if (showPrompt) {
    for (const group of groupBySink(result.paths)) {
      console.log(`\n--- Stage 2 prompt for ${formatHop(group.sink)} ---\n${buildJudgePrompt(group)}\n--- end prompt ---`);
    }
  }
  return 0;
}

/** Splits argv into positionals and `--flag [value]` options. */
function parseArgs(args: string[]): { positional: string[]; flags: Map<string, string | true> } {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--root") flags.set("root", args[++i] ?? "");
    else if (arg.startsWith("--")) flags.set(arg.slice(2), true);
    else positional.push(arg);
  }
  return { positional, flags };
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === "--version" || command === "-v") {
    console.log(`flowcheck v${VERSION}`);
    return 0;
  }
  if (command === undefined || command === "--help" || command === "-h") {
    console.log(USAGE);
    return 0;
  }

  const { positional, flags } = parseArgs(rest);
  const root = typeof flags.get("root") === "string" ? (flags.get("root") as string) : undefined;
  if (positional.length === 1 && flags.get("root") !== "") {
    if (command === "scan") return flags.has("cross-file") ? scanCrossFile(positional[0], root) : scan(positional[0]);
    if (command === "trace") return trace(positional[0], root, flags.has("show-prompt"));
  }
  console.error(USAGE);
  return EXIT_ERROR;
}

main(process.argv.slice(2)).then((code) => process.exit(code));
