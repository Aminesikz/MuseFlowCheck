// GitHub Action: the verdict (exit code + JSON → check status), anchoring findings on a PR's diff, the comment
// payloads, and the runner end to end. The end-to-end cases drive scripts/action-demo.ts --offline: the real runner and
// the real engine, with stand-ins for the model endpoint and the GitHub API (which rejects comments GitHub would).
import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  anchorFor,
  commentableLines,
  findingComment,
  fingerprint,
  postedFingerprints,
  repoPath,
  staleFixNote,
  summaryComment,
  verdict,
  type ScanResult,
} from "../src/action/report.js";
import { fixGroups } from "../src/report.js";
import type { Analysis } from "../src/engine/coverage.js";
import type { Finding } from "../src/types/index.js";

const complete: Analysis = {
  complete: true,
  maxUnresolvedPercent: 20,
  files: 3,
  filesParsed: 3,
  parseErrors: [],
  entryPointsTotal: 2,
  entryPointsResolved: 2,
  handlersTraced: 2,
  callsFollowed: 4,
  unresolved: 0,
  reasons: [],
  problems: [],
};
const incomplete: Analysis = {
  ...complete,
  complete: false,
  entryPointsResolved: 0,
  reasons: [{ reason: "dynamic require(x) — module path is computed at runtime", count: 2, names: [], example: "routes/index.js:3  require" }],
  problems: ["could not follow 2 of 2 routes (100%) — 2 handler(s) not resolved"],
};

function finding(over: Partial<Finding> = {}): Finding {
  return {
    type: "SQL Injection",
    cwe: "CWE-89",
    severity: "high",
    file: "routes/search.js",
    sourceLine: 4,
    sinkFile: "db/client.js",
    sinkLine: 12,
    taintPath: ["routes/search.js:4  const q = req.query.q", "services/find.js:8  find(q)", "db/client.js:12  pool.query(sql)"],
    explanation: "q is concatenated into the SQL text.",
    suggestedPatch: "pool.query('SELECT * FROM t WHERE name = $1', [q])",
    httpRoute: "GET /search",
    confidence: "suspected",
    ...over,
  };
}
const result = (findings: Finding[], analysis = complete): ScanResult => ({ findings, analysis });

test("verdict: only a complete scan with nothing at or above fail-on passes", () => {
  const high = finding();
  const medium = finding({ severity: "medium" });
  const cases: [number | null, ScanResult | undefined, string, string, boolean][] = [
    [0, result([]), "high", "pass", true],
    [0, result([medium]), "high", "pass", true], // below the threshold: reported, not gating
    [1, result([high]), "high", "findings", false],
    [1, result([high]), "critical", "pass", true], // a looser threshold than the engine's own gate
    [0, result([medium]), "medium", "findings", false], // a stricter one
    [1, result([high]), "none", "pass", true],
    [3, result([], incomplete), "high", "incomplete", false],
    [3, result([medium], incomplete), "high", "incomplete", false],
    [3, result([high], incomplete), "none", "incomplete", false], // fail-on none never makes an incomplete scan green
    [1, result([high], incomplete), "high", "findings", false], // the engine's 1 masks its 3; complete comes from the JSON
    [1, result([high], incomplete), "critical", "incomplete", false],
    [0, result([], incomplete), "high", "incomplete", false], // defensive: the JSON wins over a stray 0
    [3, result([]), "high", "incomplete", false], // and an exit 3 wins over a stray complete: true
    [2, result([high]), "high", "error", false],
    [2, result([]), "high", "error", false],
    [2, undefined, "high", "error", false],
    [0, undefined, "high", "error", false], // no readable output is never a pass
    [null, undefined, "high", "error", false], // killed by a signal
    [137, result([]), "high", "error", false],
  ];
  for (const [code, r, failOn, status, passed] of cases) {
    const v = verdict(code, r, failOn as never);
    assert.equal(v.status, status, `exit ${code}, fail-on ${failOn}, ${r ? `${r.findings.length} finding(s), complete ${r.analysis.complete}` : "no output"}`);
    assert.equal(v.passed, passed);
  }
  assert.match(verdict(3, result([], incomplete), "high").headline, /^INCOMPLETE ANALYSIS — not a clean bill of health/);
  assert.match(verdict(1, result([high], incomplete), "high").headline, /merge blocked\. The analysis was also INCOMPLETE\.$/);
  assert.equal(verdict(1, result([high], incomplete), "high").complete, false);
  assert.match(verdict(2, undefined, "high").headline, /not a clean bill of health/);
});

test("commentableLines: added and context lines on the head side; removed lines and no-newline markers skipped", () => {
  const patch = ["@@ -1,4 +1,5 @@", " a", "-b", "+B", "+B2", " c", "\\ No newline at end of file", "@@ -20,2 +21,2 @@", " x", "+y"].join("\n");
  assert.deepEqual([...commentableLines(patch)], [1, 2, 3, 4, 21, 22]);
  assert.deepEqual([...commentableLines(undefined)], []);
});

test("anchorFor: the sink line, else the source line, else a hop; a changed file outside the diff gets a file-level comment", () => {
  const f = finding();
  const diff = (entries: [string, number[]][]) => new Map(entries.map(([p, lines]) => [p, new Set(lines)]));
  assert.deepEqual(anchorFor(f, ".", diff([["db/client.js", [12]], ["routes/search.js", [4]]])), { path: "db/client.js", line: 12 });
  assert.deepEqual(anchorFor(f, ".", diff([["db/client.js", [1, 2]], ["routes/search.js", [4]]])), { path: "routes/search.js", line: 4 });
  assert.deepEqual(anchorFor(f, ".", diff([["services/find.js", [7, 8, 9]]])), { path: "services/find.js", line: 8 }, "a PR editing the middle of the path");
  assert.deepEqual(anchorFor(f, ".", diff([["db/client.js", [40]]])), { path: "db/client.js" });
  assert.equal(anchorFor(f, ".", diff([["README.md", [1]]])), undefined, "touches nothing the PR changed");
  // Findings are relative to the scanned directory; the PR's paths to the repository root.
  assert.deepEqual(anchorFor(f, "server", diff([["server/db/client.js", [12]]])), { path: "server/db/client.js", line: 12 });
  assert.equal(repoPath("./server/", "routes/a.js"), "server/routes/a.js");
  assert.equal(repoPath(".", "routes/a.js"), "routes/a.js");
});

test("fingerprint: stable when code only moves, distinct per class and path; read back from posted bodies", () => {
  const f = finding();
  const moved = finding({ sourceLine: 9, sinkLine: 30, taintPath: f.taintPath.map((h) => h.replace(/:(\d+)/, (_, n) => `:${Number(n) + 5}`)) });
  assert.equal(fingerprint(f), fingerprint(moved));
  assert.notEqual(fingerprint(f), fingerprint(finding({ type: "IDOR", cwe: "CWE-639" })));
  assert.notEqual(fingerprint(f), fingerprint(finding({ httpRoute: "GET /other" })));
  const body = findingComment(f, ".");
  assert.deepEqual([...postedFingerprints(["unrelated", body])], [fingerprint(f)]);
});

test("findingComment: severity badge, type and CWE, locations, taint path, why, and the fix in a fence the code cannot close", () => {
  const f = finding({ severity: "critical", suggestedPatch: "const s = ```;\nrun(s)", confidence: "confirmed", verification: { outcome: "confirmed", summary: "Rows of another tenant came back." } });
  const body = findingComment(f, "server");
  assert.match(body, /^<!-- museflowcheck:finding:[0-9a-f]{16} -->\n🔴 \*\*CRITICAL\*\* · \*\*SQL Injection\*\* · CWE-89$/m);
  assert.match(body, /`GET \/search` · `server\/routes\/search\.js:4` → `server\/db\/client\.js:12` · _✅ exploit confirmed/);
  assert.match(body, /^1\. server\/routes\/search\.js:4 {2}const q = req\.query\.q$/m);
  assert.match(body, /\*\*Why\*\*\nq is concatenated/);
  assert.match(body, /\*\*Proof\*\*\nRows of another tenant came back\./);
  assert.match(body, /\*\*Suggested fix\*\*\n````js\nconst s = ```;\nrun\(s\)\n````/);
  assert.match(findingComment(finding(), ".", { path: "db/client.js" }), /outside the diff/);
});

test("summaryComment: counts by class and severity; an incomplete scan is called out, never as a pass", () => {
  const findings = [finding(), finding({ severity: "medium", httpRoute: "GET /export", sinkLine: 20, taintPath: ["routes/export.js:3  req.query.col", "db/client.js:20  pool.query(sql)"] }), finding({ type: "IDOR", cwe: "CWE-639", severity: "high" })];
  const r = result(findings);
  const v = verdict(1, r, "high");
  const body = summaryComment({ verdict: v, result: r, failOn: "high", scanDir: ".", inline: new Set([fingerprint(findings[0])]) });
  assert.match(body, /^<!-- museflowcheck:summary -->\n## ❌ MuseFlowCheck — findings$/m);
  assert.match(body, /^\| SQL Injection \(CWE-89\) \| · \| 1 \| 1 \| · \| 2 \|$/m);
  assert.match(body, /^\| IDOR \(CWE-639\) \| · \| 1 \| · \| · \| 1 \|$/m);
  assert.match(body, /^\| \*\*All\*\* \| · \| 2 \| 1 \| · \| \*\*3\*\* \|$/m);
  assert.match(body, /1 finding\(s\) commented inline on this PR's diff; 2 elsewhere in the repository/);
  assert.match(body, /🟠 \*\*HIGH\*\* IDOR \(CWE-639\) \*\*\(gates\)\*\*/);
  assert.match(body, /detection only — findings are _suspected_/);
  assert.doesNotMatch(body, /CAUTION/);

  const blind = result([], incomplete);
  const ib = summaryComment({ verdict: verdict(3, blind, "high"), result: blind, failOn: "high", scanDir: ".", inline: new Set() });
  assert.match(ib, /## ⚠️ MuseFlowCheck — incomplete analysis/);
  assert.match(ib, /> \[!CAUTION\]\n> Code the engine could not follow was not checked/);
  assert.match(ib, /> - could not follow 2 of 2 routes/);
  assert.match(ib, /> - 2× dynamic require\(x\)/);
  assert.match(ib, /No findings in the code that could be followed\./);
  assert.doesNotMatch(ib, /✅|passed/);
});

test("findingComment and summaryComment: findings whose fixes rewrite one handler warn to fix together, and are grouped", () => {
  const sqli = finding({ file: "routes/search.js", sinkFile: undefined, sinkLine: 9, severity: "critical", suggestedPatch: 'router.get("/search", async (req, res) => {\n});' });
  const xss = finding({ type: "Cross-Site Scripting (Reflected)", cwe: "CWE-79", file: "routes/search.js", sinkFile: undefined, sinkLine: 11, taintPath: ["routes/search.js:11  res.send(q)"], suggestedPatch: 'router.get("/search", async (req, res) => {\n});' });
  const [group] = fixGroups([sqli, xss]);
  const body = findingComment(sqli, "server", undefined, group);
  assert.match(body, /\n> \[!WARNING\]\n> \*\*⚠ Fix together\.\*\* The GET \/search handler in server\/routes\/search\.js has 2 findings \(also: Cross-Site Scripting \(Reflected\) \(CWE-79\) at server\/routes\/search\.js:11\)\. The suggested fixes each rewrite the handler independently — apply them together, not in isolation, or combine them into one fix\.\n/);
  assert.ok(body.indexOf("Fix together") < body.indexOf("**Suggested fix**"));
  assert.doesNotMatch(findingComment(sqli, "server"), /Fix together/);

  // An earlier run's comment is edited only when its warning is missing, outdated, or no longer true.
  assert.equal(staleFixNote(body, sqli, "server", group), false);
  assert.equal(staleFixNote(findingComment(sqli, "server"), sqli, "server", group), true, "warning missing");
  assert.equal(staleFixNote(body.replace(":11)", ":12)"), sqli, "server", group), true, "warning outdated");
  assert.equal(staleFixNote(body, sqli, "server", undefined), true, "warning no longer true");
  assert.equal(staleFixNote(findingComment(sqli, "server"), sqli, "server", undefined), false);

  const r = result([sqli, xss, finding({ httpRoute: "GET /other" })]);
  const summary = summaryComment({ verdict: verdict(1, r, "high"), result: r, failOn: "high", scanDir: "server", inline: new Set() });
  assert.match(summary, /> \[!WARNING\]\n> \*\*Findings that share a fix — combine their fixes\.\*\*/);
  assert.match(summary, /^> - GET \/search handler in `server\/routes\/search\.js`: 🔴 \*\*CRITICAL\*\* SQL Injection \(CWE-89\) at `server\/routes\/search\.js:9` · 🟠 \*\*HIGH\*\* Cross-Site Scripting \(Reflected\) \(CWE-79\) at `server\/routes\/search\.js:11`$/m);
  assert.equal(summary.match(/^> - /gm)?.length, 1, "the finding on another route is in no group");
  assert.doesNotMatch(summaryComment({ verdict: verdict(1, result([sqli]), "high"), result: result([sqli]), failOn: "high", scanDir: ".", inline: new Set() }), /share a fix/);
});

// ---- end to end ----------------------------------------------------------------------------------------

const demo = fileURLToPath(new URL("../scripts/action-demo.ts", import.meta.url));
const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
const fixture = (name: string) => fileURLToPath(new URL(`./${name}`, import.meta.url));

interface DemoRun {
  runs: { code: number; outputs: Record<string, string>; log: string; stepSummary: string }[];
  reviewComments: { path: string; line?: number; subject_type?: string; body: string; edited?: boolean }[];
  issueComments: { body: string }[];
  rejected: { route: string; reason: string }[];
}

/** Runs the Action's runner through the demo harness, always offline, and returns everything it recorded. */
function runAction(args: string[], env: NodeJS.ProcessEnv = {}, model: "finding" | "garbage" = "finding"): Promise<DemoRun> {
  return new Promise((resolve, reject) => {
    execFile(tsx, [demo, ...args, "--offline", model, "--json"], { env: { ...process.env, ...env }, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error(`demo output was not JSON (${err?.message}):\n${stderr}`));
      }
    });
  });
}

const [onDiff, offDiff, fileLevel, blind, lenient, broken, critical] = [
  runAction([fixture("project-scan"), "--changed", "controllers/reports.js,db.js:1-2", "--runs", "2"]),
  runAction([fixture("project-scan"), "--changed", "routes/search.js"]),
  runAction([fixture("project-scan"), "--changed", "db.js:1-2"]),
  runAction([fixture("action-incomplete")]),
  runAction([fixture("action-incomplete")], { INPUT_MAX_UNRESOLVED: "100" }),
  runAction([fixture("project-scan")], {}, "garbage"),
  runAction([fixture("project-scan"), "--changed", "controllers/reports.js", "--fail-on", "critical"]),
];

test("action: a high finding on the PR's diff is commented inline on its line, the check fails, and a re-run reposts nothing", async () => {
  const r = await onDiff;
  assert.deepEqual(r.rejected, [], "every comment is one GitHub accepts");
  const [first, second] = r.runs;
  assert.equal(first.code, 1, first.log);
  assert.deepEqual(first.outputs, { status: "findings", findings: "1", gated: "1", complete: "true" });
  assert.match(first.log, /::error title=MuseFlowCheck%3A findings::1 finding\(s\) at or above high — merge blocked\./);

  // The sink (db.js:6) is outside the changed range, so the comment goes on the source line.
  assert.equal(r.reviewComments.length, 1, "posted once across two runs");
  const [c] = r.reviewComments;
  assert.deepEqual([c.path, c.line], ["controllers/reports.js", 7]);
  assert.match(c.body, /🟠 \*\*HIGH\*\* · \*\*SQL Injection\*\* · CWE-89/);
  assert.match(c.body, /`GET \/reports\/:kind` · `controllers\/reports\.js:7` → `db\.js:6` · _suspected — detection only, not executed_/);
  assert.match(c.body, /\*\*Taint path\*\*\n```\n1\. controllers\/reports\.js:7 /);
  assert.match(c.body, /\*\*Suggested fix\*\*\n```js\n/);

  assert.equal(second.code, 1);
  assert.match(second.log, /Inline comments: 0 posted, 1 already on the PR\./);
  assert.equal(r.issueComments.length, 1, "one summary comment, updated in place");
  assert.match(r.issueComments[0].body, /runs\/1001\)/, "holding the second run's result");
  assert.match(r.issueComments[0].body, /1 finding\(s\) commented inline on this PR's diff; 0 elsewhere/);
  assert.equal(first.stepSummary.trim(), r.issueComments[0].body.replace("runs/1001", "runs/1000").trim(), "the job summary carries the same report");
});

const sharedArgs = [fixture("action-shared-handler"), "--changed", "routes/search.js,server.js:2-2"];
const shared = runAction([...sharedArgs, "--runs", "2"]);

test("action: PR 1's SQLi and XSS share one handler — both comments warn to fix together, and the summary groups them", async () => {
  const r = await shared;
  assert.deepEqual(r.rejected, []);
  assert.deepEqual(r.runs.map((run) => run.code), [1, 1]);
  assert.equal(r.reviewComments.length, 2, "posted once across two runs");
  const byLine = new Map(r.reviewComments.map((c) => [c.line, c.body]));
  assert.match(byLine.get(9)!, /\*\*SQL Injection\*\* · CWE-89[\s\S]*> \*\*⚠ Fix together\.\*\* The GET \/search handler in routes\/search\.js has 2 findings \(also: Cross-Site Scripting \(Reflected\) \(CWE-79\) at routes\/search\.js:11\)/);
  assert.match(byLine.get(11)!, /\*\*Cross-Site Scripting \(Reflected\)\*\* · CWE-79[\s\S]*> \*\*⚠ Fix together\.\*\* The GET \/search handler in routes\/search\.js has 2 findings \(also: SQL Injection \(CWE-89\) at routes\/search\.js:9\)/);
  assert.match(r.runs[1].log, /Inline comments: 0 posted, 2 already on the PR\./, "an up-to-date warning is not re-edited");
  assert.match(r.issueComments[0].body, /^> - GET \/search handler in `routes\/search\.js`: .*SQL Injection \(CWE-89\) at `routes\/search\.js:9` · .*Cross-Site Scripting \(Reflected\) \(CWE-79\) at `routes\/search\.js:11`$/m);
});

test("action: a comment posted before the warning existed is edited to carry it, not posted again", async () => {
  // The SQLi comment as the first live run posted it: no warning (the XSS comment is not on the PR yet).
  const posted = (await shared).reviewComments.find((c) => c.line === 9)!;
  const old = posted.body.replace(/\n> \[!WARNING\]\n> \*\*⚠ Fix together\.\*\*[^\n]*\n/, "\n");
  assert.doesNotMatch(old, /Fix together/);
  const dir = mkdtempSync(path.join(tmpdir(), "action-seed-"));
  try {
    const seed = path.join(dir, "seed.json");
    writeFileSync(seed, JSON.stringify([{ path: posted.path, line: 9, body: old }]));
    const r = await runAction([...sharedArgs, "--seed", seed]);
    assert.deepEqual(r.rejected, []);
    assert.equal(r.reviewComments.length, 2, "the seeded SQLi comment plus a new XSS comment");
    const edited = r.reviewComments.find((c) => c.line === 9)!;
    assert.equal(edited.edited, true);
    assert.match(edited.body, /⚠ Fix together\.\*\* The GET \/search handler in routes\/search\.js has 2 findings/);
    assert.match(r.runs[0].log, /Inline comments: 1 posted, 1 already on the PR \(1 updated: same-handler warning changed\)\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("action: a finding outside the PR's changed files is not commented inline, but still counted, listed and gating", async () => {
  const r = await offDiff;
  assert.equal(r.runs[0].code, 1);
  assert.deepEqual(r.reviewComments, []);
  assert.match(r.issueComments[0].body, /0 finding\(s\) commented inline on this PR's diff; 1 elsewhere in the repository/);
  assert.match(r.issueComments[0].body, /<summary>Findings without an inline comment<\/summary>\n\n- 🟠 \*\*HIGH\*\* SQL Injection \(CWE-89\) \*\*\(gates\)\*\* `GET \/reports\/:kind` — `controllers\/reports\.js:7` → `db\.js:6`/);
});

test("action: a changed file whose flow lines are outside the diff gets a file-level comment", async () => {
  const r = await fileLevel;
  assert.deepEqual(r.rejected, []);
  assert.equal(r.reviewComments.length, 1);
  assert.deepEqual([r.reviewComments[0].path, r.reviewComments[0].line, r.reviewComments[0].subject_type], ["db.js", undefined, "file"]);
  assert.match(r.reviewComments[0].body, /outside the diff/);
});

test("action: an incomplete analysis (NodeGoat-style dynamic requires) with no findings is NOT a pass", async () => {
  const r = await blind;
  const [run] = r.runs;
  assert.equal(run.code, 1, "a failing check, never green");
  assert.deepEqual(run.outputs, { status: "incomplete", findings: "0", gated: "0", complete: "false" });
  assert.match(run.log, /::error title=MuseFlowCheck%3A INCOMPLETE ANALYSIS — not a clean bill of health::/);
  assert.deepEqual(r.reviewComments, []);
  const body = r.issueComments[0].body;
  assert.match(body, /## ⚠️ MuseFlowCheck — incomplete analysis/);
  assert.match(body, /\*\*INCOMPLETE ANALYSIS — not a clean bill of health\./);
  assert.match(body, /> - could not follow 3 of 4 routes \(75%\)/);
  assert.match(body, /dynamic require\(process\.env\.CONTRIBUTIONS_DAO/);
  assert.match(body, /\*\*Analysis:\*\* \*\*INCOMPLETE\*\*/);
  assert.doesNotMatch(body, /✅/);

  // Accepting any coverage is an explicit opt-in (max-unresolved: 100) — then, and only then, it passes.
  const ok = (await lenient).runs[0];
  assert.equal(ok.code, 0, ok.log);
  assert.equal(ok.outputs.status, "pass");
});

test("action: an engine error (a sink the model could not judge) fails the check as a scan error", async () => {
  const [run] = (await broken).runs;
  assert.equal(run.code, 1);
  assert.equal(run.outputs.status, "error");
  assert.match(run.log, /::error title=MuseFlowCheck%3A scan error::/);
});

test("action: fail-on critical lets a high finding through — still commented, the check passes", async () => {
  const r = await critical;
  assert.equal(r.runs[0].code, 0, r.runs[0].log);
  assert.deepEqual(r.runs[0].outputs, { status: "pass", findings: "1", gated: "0", complete: "true" });
  assert.equal(r.reviewComments.length, 1);
  assert.match(r.issueComments[0].body, /## ✅ MuseFlowCheck — passed\n\n\*\*No findings at or above critical; analysis complete \(1 below the threshold\)\.\*\*/);
});

test("action: with no API key (e.g. a pull request from a fork) the runner fails before scanning", () => {
  const runner = fileURLToPath(new URL("../src/action/run.ts", import.meta.url));
  const env = { PATH: process.env.PATH, META_API_KEY: "", INPUT_FAIL_ON: "high" };
  const run = spawnSync(tsx, [runner], { env, encoding: "utf8" });
  assert.equal(run.status, 1);
  assert.match(run.stdout, /::error title=MuseFlowCheck%3A no API key::META_API_KEY is empty/);
  assert.match(run.stdout, /::error title=MuseFlowCheck%3A scan error::/);
  assert.doesNotMatch(run.stdout + run.stderr, /Scanning project/, "the engine never ran");
});
