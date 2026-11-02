// GitHub Action runner: runs the engine's combined scan with --json, then reports — inline review comments on the
// PR's diff, one summary comment, the job summary and step outputs — and exits 0 only for a pass. A thin wrapper:
// detection, judging and the completeness verdict all come from the engine; this maps them onto GitHub.
//
// Inputs arrive as INPUT_* environment variables (set by action.yml) and the run's context as the standard GITHUB_*
// variables, so the same script runs locally against a stand-in API (see scripts/action-demo.ts).
import { spawn } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GitHub, GitHubError } from "./github.js";
import {
  anchorFor,
  commentableLines,
  FAIL_ON,
  findingComment,
  fingerprint,
  isGated,
  postedFingerprints,
  repoPath,
  summaryComment,
  SUMMARY_MARKER,
  verdict,
  type DiffIndex,
  type FailOn,
  type ScanResult,
  type Verdict,
} from "./report.js";

const env = process.env;
const input = (name: string, fallback = ""): string => env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`]?.trim() || fallback;
const flag = (name: string, fallback: boolean): boolean => {
  const v = input(name).toLowerCase();
  return v === "" ? fallback : v === "true" || v === "1" || v === "yes";
};

/** A workflow command (`::error ...::message`); data is escaped so a finding's text cannot inject another command. */
function command(name: string, props: Record<string, string | number | undefined>, message: string): void {
  const esc = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  const escProp = (s: string) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
  const list = Object.entries(props)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${escProp(String(v))}`)
    .join(",");
  console.log(`::${name}${list ? ` ${list}` : ""}::${esc(message)}`);
}

function setOutput(name: string, value: string | number): void {
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

/** The engine CLI next to this runner: dist/cli.js when built, src/cli.ts under tsx (execArgv carries the loader). */
function engineCommand(): string[] {
  const self = fileURLToPath(import.meta.url);
  return [...process.execArgv, path.join(path.dirname(self), "..", `cli${path.extname(self)}`)];
}

/** Runs the combined scan; stdout (the JSON) is captured, progress on stderr streams to the job log. */
function runEngine(args: string[], extraEnv: Record<string, string>): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...engineCommand(), ...args], {
      cwd: env.GITHUB_WORKSPACE || process.cwd(),
      env: { ...env, ...extraEnv, NO_COLOR: "1" },
      stdio: ["ignore", "pipe", "inherit"],
    });
    let stdout = "";
    child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
    child.on("error", (err) => {
      console.error(`✗ could not start the engine: ${err.message}`);
      resolve({ code: null, stdout });
    });
    child.on("close", (code) => resolve({ code, stdout }));
  });
}

function parseResult(stdout: string): ScanResult | undefined {
  try {
    const r = JSON.parse(stdout) as ScanResult;
    return Array.isArray(r.findings) && r.analysis && typeof r.analysis.complete === "boolean" ? r : undefined;
  } catch {
    return undefined;
  }
}

interface PullRequest {
  number: number;
  headSha: string;
}

function pullRequest(): PullRequest | undefined {
  if (!env.GITHUB_EVENT_PATH) return undefined;
  try {
    const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
    const pr = event.pull_request;
    return pr?.number && pr.head?.sha ? { number: pr.number, headSha: pr.head.sha } : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Posts an inline comment for each finding that touches the PR's diff and has not been posted before (matched by
 * fingerprint), up to `max`. Returns the fingerprints that have an inline comment, and a note when posting stopped.
 */
async function commentInline(gh: GitHub, pr: PullRequest, result: ScanResult, scanDir: string, max: number): Promise<{ inline: Set<string>; note?: string; readOnly?: boolean }> {
  const diff: DiffIndex = new Map();
  for (const f of await gh.pullFiles(pr.number)) if (f.status !== "removed") diff.set(f.filename, commentableLines(f.patch));
  const posted = postedFingerprints((await gh.reviewComments(pr.number)).map((c) => c.body));
  const inline = new Set<string>();
  let fresh = 0;
  let skipped = 0;
  for (const f of result.findings) {
    const anchor = anchorFor(f, scanDir, diff);
    if (!anchor) continue;
    const fp = fingerprint(f);
    if (posted.has(fp) || inline.has(fp)) {
      inline.add(fp); // already on the PR from an earlier run
      continue;
    }
    if (fresh >= max) {
      skipped++;
      continue;
    }
    try {
      await gh.postReviewComment(pr.number, pr.headSha, { path: anchor.path, line: anchor.line, body: findingComment(f, scanDir, anchor) });
      inline.add(fp);
      fresh++;
    } catch (err) {
      if (err instanceof GitHubError && (err.status === 403 || err.status === 401)) {
        command("warning", { title: "MuseFlowCheck: cannot comment" }, `${err.message}\nFalling back to annotations. Grant the workflow "pull-requests: write"; a pull request from a fork only gets a read-only token.`);
        return { inline, note: "the token cannot write PR comments, so findings are annotations instead", readOnly: true };
      }
      command("warning", { title: "MuseFlowCheck: inline comment not posted" }, (err as Error).message);
    }
  }
  console.log(`Inline comments: ${fresh} posted, ${inline.size - fresh} already on the PR${skipped > 0 ? `, ${skipped} over the max-comments limit` : ""}.`);
  return { inline, note: skipped > 0 ? `${skipped} more not posted: over the max-comments limit` : undefined };
}

/** Creates the summary comment, or updates the one an earlier run posted. */
async function upsertSummary(gh: GitHub, pr: PullRequest, body: string): Promise<void> {
  const existing = (await gh.issueComments(pr.number)).find((c) => c.body.startsWith(SUMMARY_MARKER));
  if (existing) await gh.updateIssueComment(existing.id, body);
  else await gh.postIssueComment(pr.number, body);
}

/** Without a PR (push, schedule, manual run), findings become annotations on the commit instead of comments. */
function annotate(result: ScanResult, scanDir: string, failOn: FailOn): void {
  for (const f of result.findings) {
    command(isGated(f, failOn) ? "error" : "warning", {
      file: repoPath(scanDir, f.sinkFile ?? f.file),
      line: f.sinkLine,
      title: `MuseFlowCheck: ${f.severity.toUpperCase()} ${f.type} (${f.cwe})`,
    }, `${f.explanation}\nSource: ${repoPath(scanDir, f.file)}:${f.sourceLine}`);
  }
}

/** The loud log line for the verdict, so a red check says why without opening the summary. */
function announce(v: Verdict): void {
  if (v.status === "pass") console.log(`✓ MuseFlowCheck: ${v.headline}`);
  else if (v.status === "incomplete") command("error", { title: "MuseFlowCheck: INCOMPLETE ANALYSIS — not a clean bill of health" }, v.headline);
  else if (v.status === "error") command("error", { title: "MuseFlowCheck: scan error" }, v.headline);
  else command("error", { title: "MuseFlowCheck: findings" }, v.headline);
  if (v.status === "findings" && !v.complete) command("warning", { title: "MuseFlowCheck: incomplete analysis" }, "The analysis was also incomplete: code the engine could not follow was not checked.");
}

async function main(): Promise<number> {
  const scanDir = input("path", ".");
  const failOn = input("fail-on", "high").toLowerCase() as FailOn;
  if (!FAIL_ON.includes(failOn)) {
    command("error", { title: "MuseFlowCheck: bad input" }, `fail-on must be one of ${FAIL_ON.join(", ")}; got "${failOn}"`);
    return 1;
  }
  const maxComments = Number(input("max-comments", "25"));

  let code: number | null = null;
  let result: ScanResult | undefined;
  if (!env.META_API_KEY?.trim()) {
    command("error", { title: "MuseFlowCheck: no API key" }, "META_API_KEY is empty. Set the api-key input from a repository secret (secrets are not passed to workflows triggered from forks).");
  } else {
    const args = ["scan", scanDir, "--json"];
    if (input("max-unresolved")) args.push("--max-unresolved", input("max-unresolved"));
    if (input("target")) args.push("--target", input("target"));
    // the target token goes through the environment, never the command line
    const extraEnv: Record<string, string> = input("target-token") ? { MUSEFLOWCHECK_TOKEN: input("target-token") } : {};
    console.log(`::group::MuseFlowCheck scan of ${scanDir}${input("target") ? ` (verified against ${input("target")})` : " (detection only)"}`);
    const run = await runEngine(args, extraEnv);
    console.log("::endgroup::");
    code = run.code;
    result = parseResult(run.stdout);
  }

  const v = verdict(code, result, failOn);
  const pr = pullRequest();
  const token = input("github-token");
  const gh = pr && token ? new GitHub(token, env.GITHUB_REPOSITORY ?? "", env.GITHUB_API_URL || undefined) : undefined;
  let inline = new Set<string>();
  let inlineNote: string | undefined;
  let readOnly = false;

  if (pr && gh && result) {
    if (flag("inline-comments", true)) {
      try {
        ({ inline, note: inlineNote, readOnly = false } = await commentInline(gh, pr, result, scanDir, Number.isFinite(maxComments) ? maxComments : 25));
      } catch (err) {
        inlineNote = "inline comments failed; see the job log";
        command("warning", { title: "MuseFlowCheck: inline comments failed" }, (err as Error).message);
      }
    }
  }
  if (result && (!gh || readOnly)) annotate(result, scanDir, failOn);

  const runUrl = env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : undefined;
  const summary = summaryComment({ verdict: v, result, failOn, scanDir, inline, inlineNote, runUrl });
  if (pr && gh && flag("summary-comment", true)) {
    try {
      await upsertSummary(gh, pr, summary);
    } catch (err) {
      command("warning", { title: "MuseFlowCheck: summary comment not posted" }, (err as Error).message);
    }
  }
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${summary}\n`);

  setOutput("status", v.status);
  setOutput("findings", result?.findings.length ?? 0);
  setOutput("gated", v.gated.length);
  setOutput("complete", String(v.complete));
  announce(v);
  return v.passed ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    command("error", { title: "MuseFlowCheck: action error" }, (err as Error).stack ?? String(err));
    process.exit(1);
  },
);
