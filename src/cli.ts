#!/usr/bin/env node
// CLI entrypoint: `flowcheck scan` / `flowcheck trace` — exit 0 clean, 1 high/critical finding, 2 usage/runtime error.
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { analyzeFile, FindingParseError } from "./engine/index.js";
import type { Project } from "ts-morph";
import {
  buildJudgePrompt,
  createProject,
  findProjectRoot,
  formatHop,
  groupBySink,
  judgeTrace,
  traceEntry,
  traceProject,
  Tracer,
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
import {
  assertLocalTarget,
  BrowserError,
  ExecBrowser,
  isXssFinding,
  Target,
  TargetError,
  verifyFindings,
  verifyPatch,
  type AuthConfig,
  type BrowserAuth,
  type VerifyDeps,
} from "./engine/verify/index.js";
import { existsSync as fileExists } from "node:fs";
import { startPatchedServer } from "./engine/verify/server.js";
import { buildXssPrompt, groupXssBySink, judgeXss, traceXssProject, type XssPath, type XssTraceResult } from "./engine/xss/index.js";
import { complete } from "./llm/meta-client.js";
import { describeApiError, loadDotEnv } from "./llm/errors.js";
import { CONFIDENCES, SEVERITIES, type Confidence, type Finding, type Verification } from "./types/index.js";

const VERSION = "0.0.0";
const USAGE = `flowcheck v${VERSION}

Usage:
  flowcheck scan <dir> [--json]                      Scan a project for every class at once — SQL injection, broken
                                                     access control / IDOR, and cross-site scripting — into one
                                                     merged Finding[], one summary and one exit code
  flowcheck scan <dir> --mode sqli [--json]          SQL injection only: find every entry point, trace request input
                                                     across files, then judge each SQL sink with the model
  flowcheck scan <file> [--json]                     Scan one JS/TS file for SQL injection (single-file)
  flowcheck scan <entry> --cross-file [--root <dir>] [--json]
                                                     Trace request input from one entry file across files, then judge
  flowcheck trace <dir|entry> [--root <dir>] [--show-prompt]
                                                     Stage 1 only: print traced paths (no API call) — every class for
                                                     a directory, SQL for an entry file; --show-prompt also prints
                                                     the Stage 2 prompt(s)
  flowcheck trace <dir> --mode sqli [--show-prompt]  SQL injection Stage 1 only (no API call)
  flowcheck scan <dir> --mode access [--route <text>] [--json]
                                                     Broken access control / IDOR: assemble per-route evidence,
                                                     then judge each unchecked route with the model
  flowcheck trace <dir> --mode access [--route <text>] [--show-prompt]
                                                     Access-control Stage 1 only (no API call)
  flowcheck scan <dir> --mode xss [--json]           Cross-site scripting: trace request input across files — directly,
                                                     or stored and read back, into server HTML or React/DOM sinks —
                                                     then judge each output reached without HTML encoding
  flowcheck trace <dir> --mode xss [--show-prompt]   XSS Stage 1 only (no API call)
  flowcheck --version

  --mode    all (default for a directory), sqli (default for a file), access, or xss
  --route   only judge (or show prompts for) routes whose "METHOD /path" contains <text>
  --json    print the findings as a JSON Finding[] on stdout (progress and summary go to stderr)

Verification (optional; proves findings by executing them against a target you run):
  --target <url>        a LOCAL target to verify against (localhost / 127.0.0.1 / ::1 / *.localhost / *.test only);
                        without it, findings stay "suspected" and nothing is executed
  --token <bearer>      bearer token the PoC requests use (a seeded low-privilege tenant token)
  --login-path <path>   instead of --token, POST credentials here and read a token from the response
  --login-body <json>   JSON credentials body for --login-path (e.g. '{"email":"a@b.test","password":"x"}')
  --token-field <name>  field holding the token in the login response (default "token")
  --identity <text>     describes the token's own scope for the PoC prompt (e.g. "it belongs to shop 1")
  --probe-range <n>     for :id-style IDOR, probe ids 1..n to discover a cross-scope target (default 20)
  --verify-patch        also apply each confirmed finding's patch to a throwaway copy and re-run the PoC
  --start-cmd <cmd>     command that starts the patched copy, honoring PORT (default "npm start")
  --ready-path <path>   path polled until the patched server answers (default "/")

XSS execution proof (optional; proves XSS findings by executing a payload in a headless browser):
  --browser-path <path> Chrome/Chromium binary to drive (auto-detected if omitted); without one, XSS stays "suspected"
  --xss-client <url>    LOCAL base URL of the client app, for findings whose sink renders in browser code (e.g. React)
  --xss-token-store <s> how the client app reads its token: "localStorage:<key>", "sessionStorage:<key>" or "window:<path>"

Exit codes: 0 no high/critical findings, 1 high/critical finding(s), 2 error`;

const EXIT_GATE = 1;
const EXIT_ERROR = 2;

/** Human-readable output: stdout normally, stderr when stdout is reserved for --json. */
let say: (text: string) => void = (text) => console.log(text);

/** When a target is configured, findings are proved against it after analysis. */
interface VerifyRuntime {
  target: Target;
  deps: VerifyDeps;
  /** XSS execution-proof config: the browser binary to launch, the client origin, and how to inject the token. */
  xss?: { browserPath: string; clientBase?: string; tokenStore?: BrowserAuth["via"] };
}
let verify: VerifyRuntime | undefined;

/** Common install locations of a Chrome/Chromium binary, tried when --browser-path is not given. */
const CHROME_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
];
function findChrome(flag: string | undefined): string | undefined {
  if (flag) return fileExists(flag) ? flag : undefined;
  return CHROME_CANDIDATES.find((p) => fileExists(p));
}

function indent(text: string, prefix = "    "): string {
  return text
    .split("\n")
    .map((line) => prefix + line)
    .join("\n");
}

function formatEvidence(label: string, e: NonNullable<Verification["baseline"]>): string {
  return `    ${label}: ${e.method} ${e.path} → ${e.status}\n      response: ${e.responseExcerpt}`;
}

function formatVerification(v: Verification): string[] {
  const lines = [`  Verification (${v.outcome}):`, indent(v.summary)];
  if (v.baseline) lines.push(formatEvidence("baseline", v.baseline));
  if (v.exploit) lines.push(formatEvidence("exploit ", v.exploit));
  if (v.patchProof) lines.push(`  Patch proof (${v.patchProof.outcome}):`, indent(v.patchProof.summary));
  return lines;
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
    ...(f.verification ? formatVerification(f.verification) : []),
  ].join("\n");
}

/** Counts by confidence, for the summary line when verification ran (e.g. "2 confirmed, 1 unverified"). */
function confidenceBreakdown(findings: Finding[]): string {
  return CONFIDENCES.map((c) => [c, findings.filter((f) => f.confidence === c).length] as const)
    .filter(([, n]) => n > 0)
    .map(([c, n]) => `${n} ${c}`)
    .join(", ");
}

/**
 * When a target is configured, proves each finding against it and returns the updated list. A bad target or a
 * failed login aborts verification (configuration error) and is reported; analysis findings are returned as-is.
 */
async function finalizeFindings(findings: Finding[], label: string, shared?: XssBrowserSession): Promise<{ findings: Finding[]; error?: boolean }> {
  if (!verify || findings.length === 0) return { findings };
  say(`\nVerification — proving ${findings.length} finding(s) against ${verify.target.base} ...\n`);
  const browser = shared ?? new XssBrowserSession(); // a combined run shares one browser; a single class owns its own
  try {
    await browser.attach(findings);
    return { findings: await verifyFindings(findings, verify.target, verify.deps) };
  } catch (err) {
    if (err instanceof TargetError) {
      console.error(`✗ Verification aborted: ${err.message}`);
      return { findings, error: true };
    }
    console.error(`✗ Verification error: ${describeError(err, label)}`);
    return { findings, error: true };
  } finally {
    if (!shared) await browser.close();
  }
}

/**
 * The headless browser for XSS execution proofs, launched on first need — verification is on, a browser is
 * configured, and there are XSS findings to prove — then reused until closed. A combined scan holds one session for
 * the whole run, so it starts Chrome at most once and closes it once, whatever happens in between.
 */
class XssBrowserSession {
  private launched?: Promise<ExecBrowser | undefined>;

  /** Attaches the browser to the verify deps when these findings need it, launching it (or trying to) only once. */
  async attach(findings: Finding[]): Promise<void> {
    if (!verify?.xss || !findings.some(isXssFinding)) return;
    this.launched ??= openXssBrowser();
    await this.launched;
  }

  async close(): Promise<void> {
    const browser = await this.launched;
    this.launched = undefined;
    if (verify) delete verify.deps.xss;
    await browser?.close();
  }
}

/**
 * Launches the headless browser for XSS execution proofs and attaches it to the verify deps. Returns undefined when
 * it cannot start — in which case XSS findings stay "suspected" (purely additive).
 */
async function openXssBrowser(): Promise<ExecBrowser | undefined> {
  if (!verify?.xss) return undefined;
  const { browserPath, clientBase, tokenStore } = verify.xss;
  try {
    let auth: BrowserAuth | undefined;
    if (tokenStore) {
      const token = await verify.target.bearerToken();
      if (token) auth = { token, via: tokenStore };
    }
    const browser = await ExecBrowser.launch({ executablePath: browserPath }, auth);
    verify.deps.xss = { browser, clientBase };
    say(`  XSS execution proof: headless browser ready (${browserPath}).\n`);
    return browser;
  } catch (err) {
    const why = err instanceof BrowserError ? err.message : (err as Error).message;
    say(`  XSS execution proof unavailable (${why}); XSS findings stay "suspected".\n`);
    return undefined;
  }
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


async function scan(file: string, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Scanning ${file} for SQL injection...\n`);
  let findings: Finding[];
  try {
    findings = await analyzeFile(file);
  } catch (err) {
    return reportError(err, file);
  }
  const final = await finalizeFindings(findings, file);
  const code = emitFindings(final.findings, json);
  say(summaryLine(final.findings));
  return final.error ? EXIT_ERROR : code;
}

/** "Summary: N finding(s), M high/critical[, confidence breakdown when verified]." */
function summaryLine(findings: Finding[]): string {
  const verified = findings.some((f) => f.confidence !== "suspected");
  const conf = verified ? ` (${confidenceBreakdown(findings)})` : "";
  return `Summary: ${findings.length} finding(s), ${gatedCount(findings)} high/critical${conf}.`;
}

/** Stage 2 for a finished SQL trace, then verification; shared by single-entry and project scans. */
async function judgeSqli(trace: TraceResult, label: string, browser?: XssBrowserSession): Promise<{ result: JudgeResult; final: { findings: Finding[]; error?: boolean } }> {
  const groups = groupBySink(trace.paths);
  let result: JudgeResult = { findings: [], failures: [], sinks: 0, calls: 0 };
  if (groups.length === 0) {
    say("Stage 1 found no candidate path into SQL text — nothing sent to the model (no single-file fallback).\n");
  } else {
    say(`Stage 2 — asking the model to judge ${groups.length} SQL execution call(s)...\n`);
    result = await judgeTrace(trace);
  }
  const judged = [...result.findings].sort(bySeverity);
  return { result, final: await finalizeFindings(judged, label, browser) };
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
  const { result, final } = await judgeSqli(trace, entry);
  let code = emitFindings(final.findings, json);
  say(summaryLine(final.findings));
  for (const f of result.failures) console.error(`✗ Judging ${f.sink} failed: ${describeError(f.error, entry)}`);
  if ((result.failures.length > 0 || final.error) && code === 0) code = EXIT_ERROR; // an unjudged sink, or a verification error, is not a clean result
  return code;
}

// ---- one class, reported alone or merged ----------------------------------------------------------

/** One vulnerability class's finished analysis and verification, reported on its own or merged into a combined scan. */
interface ClassRun {
  name: string;
  files: number;
  findings: Finding[];
  /** Rows of the class's own summary, before and after its Findings / Confidence rows. */
  before: string[];
  after: string[];
  /** The class's Stage 1/2 counts on one line, for the combined summary. */
  brief: string;
  /** Printed after the findings: unresolved calls, routes judged not vulnerable. */
  notes: string[];
  /** Judge failures, reported on stderr. */
  failures: string[];
  /** A judge failure or a verification error: the result is not clean. */
  failed: boolean;
}

/** What a combined scan shares across classes: one parsed project and one headless browser. */
interface SharedRun {
  project?: Project;
  browser?: XssBrowserSession;
}

function severityCounts(findings: Finding[]): string {
  return SEVERITIES.map((s) => `${s} ${findings.filter((f) => f.severity === s).length}`).join(", ");
}

function confidenceRow(findings: Finding[]): string[] {
  return findings.some((f) => f.confidence !== "suspected") ? [`  Confidence:     ${confidenceBreakdown(findings)}`] : [];
}

/** Reports one class on its own (a single --mode scan) and returns its exit code. */
function reportClass(run: ClassRun | undefined, json: boolean): number {
  if (!run) return EXIT_ERROR; // Stage 1 failed; already reported
  const { findings } = run;
  say(["Summary", ...run.before, `  Findings:       ${findings.length} — ${severityCounts(findings)}`, ...confidenceRow(findings), ...run.after, ""].join("\n"));
  let code = emitFindings(findings, json);
  for (const note of run.notes) say(note);
  for (const failure of run.failures) console.error(failure);
  if (run.failed && code === 0) code = EXIT_ERROR;
  return code;
}

async function runSqli(dir: string, shared: SharedRun = {}): Promise<ClassRun | undefined> {
  say(`Scanning project ${dir} for SQL injection...\n`);
  let trace: TraceResult;
  try {
    trace = traceProject(dir, new Tracer(path.resolve(dir), shared.project));
  } catch (err) {
    reportError(err, dir);
    return undefined;
  }
  const sqlText = trace.paths.filter((p) => p.sqlText).length;
  const bound = trace.paths.length - sqlText;
  say(
    [
      `Stage 1 — ${trace.files} file(s), ${trace.handlers} entry point(s) (${readingInput(trace)} read request input)`,
      `  ${sqlText} candidate path(s) into SQL text; ${bound} reach SQL only as bound parameters`,
      `  Run \`flowcheck trace ${dir}\` for every entry point and hop.`,
      "",
    ].join("\n"),
  );
  const { result, final } = await judgeSqli(trace, dir, shared.browser);
  return {
    name: "SQL injection",
    files: trace.files,
    findings: final.findings,
    before: [
      `  Files scanned:  ${trace.files}`,
      `  Entry points:   ${trace.handlers} (${readingInput(trace)} read request input)`,
      `  SQL sinks:      ${result.sinks} judged (${result.calls} model call(s)); ${bound} path(s) reach SQL only as bound parameters`,
    ],
    after: [`  Unresolved:     ${trace.unresolved.length} call(s)`],
    brief: `${result.sinks} SQL sink(s) judged (${result.calls} model call(s)); ${bound} path(s) reach SQL only as bound parameters`,
    notes: [formatUnresolved(trace)],
    failures: result.failures.map((f) => `✗ Judging ${f.sink} failed: ${describeError(f.error, dir)}`),
    failed: result.failures.length > 0 || final.error === true,
  };
}

async function scanProject(dir: string, json: boolean): Promise<number> {
  loadDotEnv();
  return reportClass(await runSqli(dir), json);
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

async function runAccess(dir: string, filter: string | undefined, shared: SharedRun = {}): Promise<ClassRun | undefined> {
  say(`Scanning project ${dir} for broken access control / IDOR...\n`);
  let ctx: AccessContext;
  try {
    ctx = assembleAccessContext(dir, shared.project);
  } catch (err) {
    reportError(err, dir);
    return undefined;
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
  const judged = [...result.findings].sort(bySeverity);
  const final = await finalizeFindings(judged, dir, shared.browser);
  const guarded = ctx.routes.filter((r) => r.status === "guarded").length;
  return {
    name: "Access control",
    files: ctx.files,
    findings: final.findings,
    before: [
      `  Files scanned:  ${ctx.files}`,
      `  Routes:         ${ctx.routes.length} (${guarded} guarded)`,
      `  Judged:         ${result.calls} route(s); ${result.cleared.length} judged not vulnerable`,
    ],
    after: [],
    brief: `${ctx.routes.length} route(s), ${guarded} guarded; ${result.calls} judged, ${result.cleared.length} judged not vulnerable`,
    notes: result.cleared.map((r) => `Judged not vulnerable: ${routeLabel(r)}`),
    failures: result.failures.map((f) => `✗ Judging ${f.route} failed: ${describeError(f.error, dir)}`),
    failed: result.failures.length > 0 || final.error === true,
  };
}

async function scanAccess(dir: string, filter: string | undefined, json: boolean): Promise<number> {
  loadDotEnv();
  return reportClass(await runAccess(dir, filter), json);
}

// ---- XSS mode -------------------------------------------------------------------------------

function formatXssPath(p: XssPath): string[] {
  return p.hops.map((h) => `    [${h.kind.padEnd(9)}] ${formatHop(h)}`);
}

const XSS_OUTPUT: Record<XssPath["context"], string> = {
  markup: "placed into markup",
  response: "written to the response",
  "dom-html": "inserted as HTML in the browser",
  "jsx-text": "rendered as JSX text",
};

const XSS_REACH: Record<NonNullable<XssPath["reach"]>["level"], string> = {
  public: "public",
  authenticated: "any signed-in user",
  "own-scope": "owning scope only",
};

/** `(GET /x) — placed into markup, stored in t.col by PUT /y, reach: public (routes/x.js:3)` */
function xssHeading(p: XssPath): string {
  const stored = p.stored ? `, stored in ${p.stored}${p.writtenBy ? ` by ${p.writtenBy}` : ""}${p.reach ? `, reach: ${XSS_REACH[p.reach.level]} (${p.reach.at})` : ""}` : "";
  return `${p.route ? ` (${p.route})` : ""} — ${XSS_OUTPUT[p.context]}${stored}`;
}

function formatXssTrace(trace: XssTraceResult): string {
  const raw = trace.xss.filter((p) => !p.encoded);
  const encoded = trace.xss.filter((p) => p.encoded);
  const out = [`XSS — Stage 1 (root: ${trace.root})`, `  Files scanned: ${trace.files}`];
  out.push(`  Request handlers found: ${trace.handlers} (${readingInput(trace)} read request input)`);
  out.push(...trace.entryPoints.map(formatEntryPoint), "", `Candidate paths into HTML output without encoding: ${raw.length}`);
  raw.forEach((p, i) => out.push(`  Path ${i + 1}${xssHeading(p)}:`, ...formatXssPath(p)));
  out.push("", `Paths reaching output only encoded or escaped (not sent to the model): ${encoded.length}`);
  for (const p of encoded) out.push(`  ${formatHop(p.hops[0])}${xssHeading(p)}\n    ⤷ ${formatHop(p.hops.at(-1)!)}\n      ${p.context === "jsx-text" ? "" : "encoded by "}${p.encoder ?? "an encoding step"}`);
  out.push("", formatUnresolved(trace));
  return out.join("\n");
}

function traceXss(dir: string, showPrompt: boolean): number {
  let trace: XssTraceResult;
  try {
    trace = traceXssProject(dir);
  } catch (err) {
    return reportError(err, dir);
  }
  say(formatXssTrace(trace));
  if (showPrompt) {
    for (const group of groupXssBySink(trace.xss)) {
      say(`\n--- Stage 2 prompt for ${formatHop(group.sink)} ---\n${buildXssPrompt(group)}\n--- end prompt ---`);
    }
  }
  return 0;
}

async function runXss(dir: string, shared: SharedRun = {}): Promise<ClassRun | undefined> {
  say(`Scanning project ${dir} for cross-site scripting...\n`);
  let trace: XssTraceResult;
  try {
    trace = traceXssProject(dir, shared.project);
  } catch (err) {
    reportError(err, dir);
    return undefined;
  }
  const groups = groupXssBySink(trace.xss);
  const encoded = trace.xss.filter((p) => p.encoded);
  say(
    [
      `Stage 1 — ${trace.files} file(s), ${trace.handlers} entry point(s) (${readingInput(trace)} read request input)`,
      `  ${trace.xss.length - encoded.length} candidate path(s) into HTML output without encoding (${trace.xss.filter((p) => !p.encoded && p.stored).length} stored); ${encoded.length} reach output only encoded or escaped`,
      ...encoded.map((p) => `  ${p.context === "jsx-text" ? "escaped" : "encoded"} (not sent): ${formatHop(p.hops.at(-1)!)} — ${p.context === "jsx-text" ? "" : "by "}${p.encoder ?? "an encoding step"}`),
      `  Run \`flowcheck trace ${dir} --mode xss\` for every entry point and hop.`,
      "",
      groups.length > 0
        ? `Stage 2 — asking the model to judge ${groups.length} HTML output(s)...\n`
        : "Stage 1 found no request input reaching HTML output without encoding — nothing sent to the model.\n",
    ].join("\n"),
  );
  const result = groups.length > 0 ? await judgeXss(trace) : { findings: [], failures: [], sinks: 0, calls: 0 };
  const judged = [...result.findings].sort(bySeverity);
  const final = await finalizeFindings(judged, dir, shared.browser); // proves XSS findings in a headless browser when --target is set
  return {
    name: "XSS",
    files: trace.files,
    findings: final.findings,
    before: [
      `  Files scanned:  ${trace.files}`,
      `  Entry points:   ${trace.handlers} (${readingInput(trace)} read request input)`,
      `  HTML outputs:   ${result.sinks} judged (${result.calls} model call(s)); ${encoded.length} path(s) reach output only encoded or escaped`,
    ],
    after: [`  Unresolved:     ${trace.unresolved.length} call(s)`],
    brief: `${result.sinks} HTML output(s) judged (${result.calls} model call(s)); ${encoded.length} path(s) reach output only encoded or escaped`,
    notes: [formatUnresolved(trace)],
    failures: result.failures.map((f) => `✗ Judging ${f.sink} failed: ${describeError(f.error, dir)}`),
    failed: result.failures.length > 0 || final.error === true,
  };
}

async function scanXss(dir: string, json: boolean): Promise<number> {
  loadDotEnv();
  return reportClass(await runXss(dir), json);
}

// ---- combined mode ------------------------------------------------------------------------------

/**
 * Scans a project for every class — SQL injection, access control, XSS — in one run. Each class runs its Stage 1,
 * Stage 2 and verification exactly as its own --mode does, over one shared parsed project and one shared headless
 * browser (closed once, even on error). Then one merged Finding[], one summary and one exit code. Findings are never
 * merged across classes: a route with both an injection and an IDOR yields one finding of each.
 */
async function scanAll(dir: string, filter: string | undefined, json: boolean): Promise<number> {
  loadDotEnv();
  say(`Scanning project ${dir} for SQL injection, broken access control / IDOR and cross-site scripting...\n`);
  const shared: SharedRun = { project: createProject(), browser: new XssBrowserSession() };
  const names = ["SQL injection", "Access control", "XSS"];
  let runs: (ClassRun | undefined)[];
  try {
    runs = [await runSqli(dir, shared), await runAccess(dir, filter, shared), await runXss(dir, shared)];
  } finally {
    await shared.browser!.close();
  }
  const done = runs.filter((r): r is ClassRun => r !== undefined);
  const findings = done.flatMap((r) => r.findings).sort(bySeverity); // stable: class order within a severity
  const perClass = runs.map((r, i) => {
    const label = `  ${`${names[i]}:`.padEnd(16)}`;
    if (!r) return `${label}not scanned (Stage 1 failed)`;
    const bySev = SEVERITIES.map((s) => [s, r.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
    const sev = bySev.length > 0 ? ` (${bySev.map(([s, n]) => `${s} ${n}`).join(", ")})` : "";
    return `${label}${r.findings.length} finding(s)${sev} — ${r.brief}`;
  });
  say(
    [
      "Summary",
      `  Files scanned:  ${Math.max(0, ...done.map((r) => r.files))}`,
      ...perClass,
      `  Findings:       ${findings.length} — ${severityCounts(findings)}`,
      ...confidenceRow(findings),
      "",
    ].join("\n"),
  );
  let code = emitFindings(findings, json);
  for (const r of done) for (const note of r.notes) say(`${r.name} — ${note}`);
  for (const r of done) for (const failure of r.failures) console.error(failure);
  if (runs.some((r) => !r || r.failed) && code === 0) code = EXIT_ERROR;
  return code;
}

function traceAll(dir: string, filter: string | undefined, showPrompt: boolean): number {
  const codes = [trace(dir, undefined, showPrompt)];
  say("");
  codes.push(traceAccess(dir, filter, showPrompt));
  say("");
  codes.push(traceXss(dir, showPrompt));
  return Math.max(...codes);
}

/** Flags that take a value. */
const VALUE_FLAGS = new Set(["root", "mode", "route", "target", "token", "login-path", "login-body", "token-field", "identity", "probe-range", "start-cmd", "ready-path", "browser-path", "xss-client", "xss-token-store"]);

/** Builds the verification runtime from the flags, or undefined when no `--target` is given. Throws on bad config. */
function buildVerifyRuntime(value: (name: string) => string | undefined, patch: boolean, dir: string): VerifyRuntime | undefined {
  const url = value("target");
  if (url === undefined) return undefined;

  let auth: AuthConfig = { kind: "none" };
  const token = value("token");
  const loginPath = value("login-path");
  if (token !== undefined) {
    auth = { kind: "token", token };
  } else if (loginPath !== undefined) {
    let body: Record<string, unknown> = {};
    try {
      body = JSON.parse(value("login-body") ?? "{}");
    } catch {
      throw new TargetError("--login-body must be valid JSON");
    }
    auth = { kind: "login", path: loginPath, body, tokenField: value("token-field") ?? "token" };
  }

  const target = new Target({ url, auth }); // throws TargetError for a non-local host
  const probeRaw = value("probe-range");
  const range = probeRaw === undefined ? 20 : Number(probeRaw);
  if (!Number.isInteger(range) || range < 1 || range > 1000) {
    throw new TargetError(`--probe-range must be an integer between 1 and 1000, got ${JSON.stringify(probeRaw)}`);
  }
  const deps: VerifyDeps = { complete, identityHint: value("identity"), probe: { range } };
  if (patch) {
    const { traceRoot, projectRoot } = resolveRoots(dir, value("root"));
    deps.patchProof = verifyPatch({
      projectDir: projectRoot, // copied and started; has the package.json/node_modules `npm start` needs
      sourceRoot: traceRoot, // what the findings' file paths are relative to
      start: (copyDir) => startPatchedServer(copyDir, { command: value("start-cmd") ?? "npm start", readyPath: value("ready-path"), auth }),
    });
  }
  return { target, deps, xss: xssConfig(value) };
}

/** XSS execution-proof config from the flags; undefined when no headless browser is available. */
function xssConfig(value: (name: string) => string | undefined): VerifyRuntime["xss"] | undefined {
  const browserPath = findChrome(value("browser-path"));
  if (!browserPath) {
    if (value("browser-path") !== undefined) throw new TargetError(`--browser-path ${JSON.stringify(value("browser-path"))} is not a file`);
    return undefined; // no browser found; XSS findings will stay "suspected"
  }
  const clientRaw = value("xss-client");
  const clientBase = clientRaw !== undefined ? assertLocalTarget(clientRaw) : undefined; // throws for a non-local client
  let tokenStore: BrowserAuth["via"] | undefined;
  const store = value("xss-token-store");
  if (store !== undefined) {
    const [kind, ...rest] = store.split(":");
    const spec = rest.join(":");
    if ((kind === "localStorage" || kind === "sessionStorage") && spec) tokenStore = { kind, key: spec };
    else if (kind === "window" && spec) tokenStore = { kind: "window", path: spec };
    else throw new TargetError('--xss-token-store must be "localStorage:<key>", "sessionStorage:<key>" or "window:<path>"');
  }
  return { browserPath, clientBase, tokenStore };
}

/**
 * Splits the scan target into the trace root (what findings' paths are relative to) and the runnable project root
 * (the nearest directory with a package.json, which patch proof copies and starts). They differ when only a subtree
 * of a project is scanned, e.g. `scan ./server` in a repo whose package.json is at the root.
 */
function resolveRoots(target: string, rootFlag: string | undefined): { traceRoot: string; projectRoot: string } {
  const abs = path.resolve(target);
  if (isDirectory(abs)) {
    const projectRoot = existsSync(path.join(abs, "package.json")) ? abs : findProjectRoot(abs);
    return { traceRoot: abs, projectRoot };
  }
  // A single entry file: the trace root is --root or the file's own project root.
  return { traceRoot: path.resolve(rootFlag ?? findProjectRoot(abs)), projectRoot: findProjectRoot(abs) };
}

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
  // Without --mode a project directory gets every class; a single file (or --cross-file entry) can only be SQL.
  const wholeProject = positional.length === 1 && isDirectory(positional[0]) && !flags.has("cross-file");
  const mode = value("mode") ?? (wholeProject ? "all" : "sqli");
  const json = flags.has("json");
  if (json) say = (text) => console.error(text);
  const emptyValue = [...VALUE_FLAGS].some((f) => flags.get(f) === "");
  if (positional.length === 1 && !emptyValue && (mode === "sqli" || mode === "access" || mode === "xss" || mode === "all")) {
    const [target] = positional;
    if (command === "scan") {
      try {
        verify = buildVerifyRuntime(value, flags.has("verify-patch"), target);
      } catch (err) {
        console.error(`✗ ${err instanceof TargetError ? err.message : describeError(err, target)}`);
        return EXIT_ERROR;
      }
    }
    if (mode === "all") {
      if (!isDirectory(target)) {
        console.error("✗ --mode all scans a project directory; use --mode sqli (or no --mode) for a single file.");
        return EXIT_ERROR;
      }
      if (command === "scan") return scanAll(target, value("route"), json);
      if (command === "trace") return traceAll(target, value("route"), flags.has("show-prompt"));
    }
    if (mode === "access") {
      if (!isDirectory(target)) {
        console.error("✗ --mode access scans a project directory (routes, middleware and schema are read together).");
        return EXIT_ERROR;
      }
      if (command === "scan") return scanAccess(target, value("route"), json);
      if (command === "trace") return traceAccess(target, value("route"), flags.has("show-prompt"));
    }
    if (mode === "xss") {
      if (!isDirectory(target)) {
        console.error("✗ --mode xss scans a project directory.");
        return EXIT_ERROR;
      }
      if (command === "scan") return scanXss(target, json);
      if (command === "trace") return traceXss(target, flags.has("show-prompt"));
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
