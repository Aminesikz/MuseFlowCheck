#!/usr/bin/env node
// CLI entrypoint: `flowcheck scan` / `flowcheck trace` — exit 0 clean, 1 high/critical finding, 2 usage/runtime error.
import { statSync } from "node:fs";
import { analyzeFile, FindingParseError } from "./engine/index.js";
import {
  buildJudgePrompt,
  formatHop,
  groupBySink,
  judgeTrace,
  traceEntry,
  traceProject,
  type EntryPoint,
  type JudgeResult,
  type TraceResult,
} from "./engine/crossfile/index.js";
import {
  assembleAccessContext,
  buildAccessPrompt,
  candidates,
  judgeAccess,
  routeLabel,
  scopingEvidence,
  secureSiblings,
  type AccessContext,
  type AccessRoute,
} from "./engine/access/index.js";
import { describeApiError, loadDotEnv } from "./llm/errors.js";
import { SEVERITIES, type Finding } from "./types/index.js";

const VERSION = "0.0.0";
const USAGE = `flowcheck v${VERSION}

Usage:
  flowcheck scan <dir> [--json]                      Scan a project: find every entry point, trace request input
                                                     across files, then judge each SQL sink with the model
  flowcheck scan <file> [--json]                     Scan one JS/TS file for SQL injection (single-file)
  flowcheck scan <entry> --cross-file [--root <dir>] [--json]
                                                     Trace request input from one entry file across files, then judge
  flowcheck trace <dir|entry> [--root <dir>] [--show-prompt]
                                                     Stage 1 only: print traced paths (no API call);
                                                     --show-prompt also prints the Stage 2 prompt(s)
  flowcheck scan <dir> --mode access [--route <text>] [--json]
                                                     Broken access control / IDOR: assemble per-route evidence,
                                                     then judge each unchecked route with the model
  flowcheck trace <dir> --mode access [--route <text>] [--show-prompt]
                                                     Access-control Stage 1 only (no API call)
  flowcheck --version

  --mode   sqli (default) or access
  --route  only judge (or show prompts for) routes whose "METHOD /path" contains <text>
  --json   print the findings as a JSON Finding[] on stdout (progress and summary go to stderr)

Exit codes: 0 no high/critical findings, 1 high/critical finding(s), 2 error`;

const EXIT_GATE = 1;
const EXIT_ERROR = 2;

/** Human-readable output: stdout normally, stderr when stdout is reserved for --json. */
let say: (text: string) => void = (text) => console.log(text);

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

function formatEntryPoint(e: EntryPoint): string {
  const route = e.route ? `${e.route}  ` : "";
  const registered = e.registeredAt ? ` (registered at ${e.registeredAt})` : "";
  const input = e.readsInput ? "" : " — reads no request input";
  return `  ${route}${e.file}:${e.line}  ${e.name}${registered}${input}`;
}

function readingInput(trace: TraceResult): number {
  return trace.entryPoints.filter((e) => e.readsInput).length;
}

function formatTrace(trace: TraceResult): string {
  const sqlText = trace.paths.filter((p) => p.sqlText);
  const bound = trace.paths.filter((p) => !p.sqlText);
  const out = [`Stage 1 — trace from ${trace.entry} (root: ${trace.root})`];
  if (trace.files > 1) out.push(`  Files scanned: ${trace.files}`);
  out.push(`  Request handlers found: ${trace.handlers} (${readingInput(trace)} read request input)`);
  out.push(...trace.entryPoints.map(formatEntryPoint), "", `Candidate paths into SQL text: ${sqlText.length}`);
  sqlText.forEach((p, i) => {
    out.push(`  Path ${i + 1}:`);
    for (const h of p.hops) out.push(`    [${h.kind.padEnd(9)}] ${formatHop(h)}`);
  });
  out.push("", `Paths reaching SQL only as bound parameters (not sent to the model): ${bound.length}`);
  for (const p of bound) out.push(`  ${formatHop(p.hops[0])}\n    ⤷ ${formatHop(p.hops.at(-1)!)}`);
  out.push("", formatUnresolved(trace));
  out.push("", `Tainted calls leaving the project (not followed): ${trace.external.length || "none"}`);
  for (const e of trace.external) out.push(`  ${e.file}:${e.line}  ${e.call} — ${e.target}`);
  return out.join("\n");
}

function formatUnresolved(trace: TraceResult): string {
  const lines = trace.unresolved.map((u) => `  ${u.file}:${u.line}  ${u.call} — ${u.reason}`);
  return [`Unresolved calls (where a trace broke): ${trace.unresolved.length || "none"}`, ...lines].join("\n");
}

function describeError(err: unknown, file: string): string {
  if (err instanceof FindingParseError) {
    return `Could not parse model response: ${err.message}\n\n--- raw model response ---\n${err.raw}\n--- end ---`;
  }
  if ((err as NodeJS.ErrnoException).code === "ENOENT") return `File not found: ${file}`;
  return describeApiError(err);
}

function reportError(err: unknown, file: string): number {
  console.error(`✗ ${describeError(err, file)}`);
  return EXIT_ERROR;
}

const bySeverity = (a: Finding, b: Finding) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);

function gatedCount(findings: Finding[]): number {
  return findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
}

/** Prints findings (or emits them as JSON) and returns the CI-gate exit code. */
function emitFindings(findings: Finding[], json: boolean): number {
  if (json) console.log(JSON.stringify(findings, null, 2));
  else findings.forEach((f, i) => say(formatFinding(f, i + 1) + "\n"));
  return gatedCount(findings) > 0 ? EXIT_GATE : 0;
}

function printFindings(findings: Finding[], json: boolean): number {
  const code = emitFindings(findings, json);
  say(`Summary: ${findings.length} finding(s), ${gatedCount(findings)} high/critical.`);
  return code;
}

async function scan(file: string, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Scanning ${file} for SQL injection...\n`);
  try {
    return printFindings(await analyzeFile(file), json);
  } catch (err) {
    return reportError(err, file);
  }
}

/** Stage 2 plus output for a finished trace; shared by single-entry and project scans. */
async function judgeAndReport(trace: TraceResult, label: string, json: boolean, project: boolean): Promise<number> {
  const groups = groupBySink(trace.paths);
  let result: JudgeResult = { findings: [], failures: [], sinks: 0, calls: 0 };
  if (groups.length === 0) {
    say("Stage 1 found no candidate path into SQL text — nothing sent to the model (no single-file fallback).\n");
  } else {
    say(`Stage 2 — asking the model to judge ${groups.length} SQL execution call(s)...\n`);
    result = await judgeTrace(trace);
  }
  const findings = [...result.findings].sort(bySeverity);

  if (project) {
    const counts = SEVERITIES.map((s) => `${s} ${findings.filter((f) => f.severity === s).length}`).join(", ");
    say(
      [
        "Summary",
        `  Files scanned:  ${trace.files}`,
        `  Entry points:   ${trace.handlers} (${readingInput(trace)} read request input)`,
        `  SQL sinks:      ${result.sinks} judged (${result.calls} model call(s)); ${trace.paths.filter((p) => !p.sqlText).length} path(s) reach SQL only as bound parameters`,
        `  Findings:       ${findings.length} — ${counts}`,
        `  Unresolved:     ${trace.unresolved.length} call(s)`,
        "",
      ].join("\n"),
    );
  }
  let code = emitFindings(findings, json);
  if (!project) say(`Summary: ${findings.length} finding(s), ${gatedCount(findings)} high/critical.`);
  if (project) say(formatUnresolved(trace));

  for (const f of result.failures) console.error(`✗ Judging ${f.sink} failed: ${describeError(f.error, label)}`);
  if (result.failures.length > 0 && code === 0) code = EXIT_ERROR; // an unjudged sink is not a clean result
  return code;
}

async function scanCrossFile(entry: string, root: string | undefined, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Cross-file scan of ${entry} for SQL injection...\n`);
  let trace: TraceResult;
  try {
    trace = traceEntry(entry, root);
  } catch (err) {
    return reportError(err, entry);
  }
  say(formatTrace(trace) + "\n");
  return judgeAndReport(trace, entry, json, false);
}

async function scanProject(dir: string, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Scanning project ${dir} for SQL injection...\n`);
  let trace: TraceResult;
  try {
    trace = traceProject(dir);
  } catch (err) {
    return reportError(err, dir);
  }
  const sqlText = trace.paths.filter((p) => p.sqlText).length;
  say(
    [
      `Stage 1 — ${trace.files} file(s), ${trace.handlers} entry point(s) (${readingInput(trace)} read request input)`,
      `  ${sqlText} candidate path(s) into SQL text; ${trace.paths.length - sqlText} reach SQL only as bound parameters`,
      `  Run \`flowcheck trace ${dir}\` for every entry point and hop.`,
      "",
    ].join("\n"),
  );
  return judgeAndReport(trace, dir, json, true);
}

function trace(target: string, root: string | undefined, showPrompt: boolean): number {
  let result: TraceResult;
  try {
    result = isDirectory(target) ? traceProject(target) : traceEntry(target, root);
  } catch (err) {
    return reportError(err, target);
  }
  say(formatTrace(result));
  if (showPrompt) {
    for (const group of groupBySink(result.paths)) {
      say(`\n--- Stage 2 prompt for ${formatHop(group.sink)} ---\n${buildJudgePrompt(group)}\n--- end prompt ---`);
    }
  }
  return 0;
}

function isDirectory(target: string): boolean {
  try {
    return statSync(target).isDirectory();
  } catch {
    return false;
  }
}

// ---- access-control mode ----------------------------------------------------------------------

function formatAccessRoute(ctx: AccessContext, r: AccessRoute): string {
  const out = [`${r.status.toUpperCase().padEnd(13)} ${routeLabel(r)}  (${r.handler.file}:${r.handler.startLine})`];
  if (r.status === "public" || r.status === "no-identifier" || r.status === "unscoped") return `${out[0]} — ${r.reason}`;
  if (r.identity) {
    const via = r.identity.middleware ? ` — set by ${r.identity.middleware.name} (${r.identity.middleware.file})` : "";
    out.push(`    identity: ${r.identity.expression} {${r.identity.fields.join(", ")}}${via}`);
  }
  for (const a of r.accesses) {
    const sink = a.path.hops.at(-1)!;
    out.push(`    access:   [${a.kind}] ${a.location}.${a.field} → ${a.tables.join(", ")}${a.column ? `.${a.column}` : ""}  (${sink.file}:${sink.line})`);
  }
  for (const g of r.guards) out.push(`    check:    ${g.kind} at ${g.file}:${g.line}: ${g.code}`);
  if (r.status === "candidate") {
    for (const line of scopingEvidence(ctx, r)) out.push(`    scoping:  ${line}`);
    const siblings = secureSiblings(ctx, r).map(routeLabel);
    out.push(`    siblings: ${siblings.join(", ") || "none found"}`);
  }
  return out.join("\n");
}

function accessCounts(ctx: AccessContext): string {
  const n = (s: AccessRoute["status"]) => ctx.routes.filter((r) => r.status === s).length;
  return `${ctx.routes.length} route(s) — ${n("candidate")} unchecked candidate(s), ${n("guarded")} guarded, ${n("unscoped")} on unscoped data, ${n("no-identifier")} without a request identifier, ${n("public")} unauthenticated`;
}

function traceAccess(dir: string, filter: string | undefined, showPrompt: boolean): number {
  let ctx: AccessContext;
  try {
    ctx = assembleAccessContext(dir);
  } catch (err) {
    return reportError(err, dir);
  }
  const schema = ctx.schemaFiles.length > 0 ? `${ctx.schemaFiles.join(", ")} (${ctx.schema.length} table(s))` : "none found";
  say(
    [
      `Access control — Stage 1 (root: ${ctx.root})`,
      `  Files scanned: ${ctx.files} · schema: ${schema}`,
      `  ${accessCounts(ctx)}`,
      "",
      ...ctx.routes.filter((r) => !filter || routeLabel(r).includes(filter)).map((r) => formatAccessRoute(ctx, r)),
    ].join("\n"),
  );
  if (showPrompt) {
    for (const r of candidates(ctx, filter)) say(`\n--- Stage 2 prompt for ${routeLabel(r)} ---\n${buildAccessPrompt(ctx, r)}\n--- end prompt ---`);
  }
  return 0;
}

async function scanAccess(dir: string, filter: string | undefined, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Scanning project ${dir} for broken access control / IDOR...\n`);
  let ctx: AccessContext;
  try {
    ctx = assembleAccessContext(dir);
  } catch (err) {
    return reportError(err, dir);
  }
  const toJudge = candidates(ctx, filter);
  say(
    [
      `Stage 1 — ${ctx.files} file(s); ${accessCounts(ctx)}`,
      ...ctx.routes.filter((r) => r.status === "guarded").map((r) => `  guarded (not sent): ${routeLabel(r)} — ${r.guards[0].kind} at ${r.guards[0].file}:${r.guards[0].line}`),
      `  Run \`flowcheck trace ${dir} --mode access\` for the evidence on every route.`,
      "",
      toJudge.length > 0
        ? `Stage 2 — asking the model to judge ${toJudge.length} route(s)${filter ? ` matching "${filter}"` : ""}...\n`
        : "Stage 1 found no unchecked candidate route — nothing sent to the model.\n",
    ].join("\n"),
  );
  const result = toJudge.length > 0 ? await judgeAccess(ctx, filter) : { findings: [], failures: [], cleared: [], calls: 0 };
  const findings = [...result.findings].sort(bySeverity);
  const counts = SEVERITIES.map((s) => `${s} ${findings.filter((f) => f.severity === s).length}`).join(", ");
  say(
    [
      "Summary",
      `  Files scanned:  ${ctx.files}`,
      `  Routes:         ${ctx.routes.length} (${ctx.routes.filter((r) => r.status === "guarded").length} guarded)`,
      `  Judged:         ${result.calls} route(s); ${result.cleared.length} judged not vulnerable`,
      `  Findings:       ${findings.length} — ${counts}`,
      "",
    ].join("\n"),
  );
  let code = emitFindings(findings, json);
  for (const r of result.cleared) say(`Judged not vulnerable: ${routeLabel(r)}`);
  for (const f of result.failures) console.error(`✗ Judging ${f.route} failed: ${describeError(f.error, dir)}`);
  if (result.failures.length > 0 && code === 0) code = EXIT_ERROR;
  return code;
}

/** Flags that take a value: `--root <dir>`, `--mode <name>`, `--route <text>`. */
const VALUE_FLAGS = new Set(["root", "mode", "route"]);

/** Splits argv into positionals and `--flag [value]` options. */
function parseArgs(args: string[]): { positional: string[]; flags: Map<string, string | true> } {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--") && VALUE_FLAGS.has(arg.slice(2))) flags.set(arg.slice(2), args[++i] ?? "");
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
  const value = (name: string) => (typeof flags.get(name) === "string" ? (flags.get(name) as string) : undefined);
  const root = value("root");
  const mode = value("mode") ?? "sqli";
  const json = flags.has("json");
  if (json) say = (text) => console.error(text);
  const emptyValue = [...VALUE_FLAGS].some((f) => flags.get(f) === "");
  if (positional.length === 1 && !emptyValue && (mode === "sqli" || mode === "access")) {
    const [target] = positional;
    if (mode === "access") {
      if (!isDirectory(target)) {
        console.error("✗ --mode access scans a project directory (routes, middleware and schema are read together).");
        return EXIT_ERROR;
      }
      if (command === "scan") return scanAccess(target, value("route"), json);
      if (command === "trace") return traceAccess(target, value("route"), flags.has("show-prompt"));
    }
    if (command === "scan") {
      if (isDirectory(target)) return scanProject(target, json);
      return flags.has("cross-file") ? scanCrossFile(target, root, json) : scan(target, json);
    }
    if (command === "trace") return trace(target, root, flags.has("show-prompt"));
  }
  console.error(USAGE);
  return EXIT_ERROR;
}

main(process.argv.slice(2)).then((code) => process.exit(code));
