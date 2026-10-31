// Incomplete analysis: a scan that could not follow most of the target must not pass as clean. Drives the real CLI
// offline (an unreachable model endpoint: none of these projects has a candidate to judge) over a project written in
// a style the tracer cannot follow, and checks the warning, the exit code and the --json analysis.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import type { Coverage } from "../src/engine/crossfile/index.js";
import { assessCoverage } from "../src/engine/coverage.js";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
const env = { ...process.env, META_API_KEY: "offline-test", META_BASE_URL: "http://127.0.0.1:9", META_MODEL: "none" };
const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-coverage-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function project(name: string, files: Record<string, string>): string {
  const dir = path.join(tmp, name);
  for (const [file, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), text);
  }
  return dir;
}

function scan(...args: string[]) {
  const run = spawnSync(tsx, [cli, "scan", ...args], { cwd: tmp, env, encoding: "utf8" });
  return { code: run.status, stdout: run.stdout, stderr: run.stderr };
}

// Handlers and the data layer are loaded through computed module paths, which the tracer cannot follow: two of three
// routes, their middleware and every database call are out of its reach — and the unreached data layer builds SQL
// from request input.
const opaque = project("opaque", {
  "routes/index.js": [
    'const load = (name) => require("./" + name);',
    "module.exports = (app) => {",
    '  const notes = load("notes");',
    "  const requireLogin = notes.requireLogin;",
    '  app.get("/notes", requireLogin, notes.list);',
    '  app.post("/notes", requireLogin, notes.add);',
    '  app.get("/health", (req, res) => res.send("ok"));',
    "};",
    "",
  ].join("\n"),
  "routes/notes.js": [
    "const dao = require(process.env.NOTES_DAO);",
    'exports.requireLogin = (req, res, next) => (req.session.userId ? next() : res.redirect("/login"));',
    'exports.list = (req, res) => dao.byOwner(req.query.owner, (err, rows) => res.json(rows));',
    'exports.add = (req, res) => dao.insert(req.body.text, () => res.redirect("/notes"));',
    "",
  ].join("\n"),
  "data/notes-dao.js": [
    "const db = require('pg');",
    "exports.byOwner = (owner, cb) => db.query(\"SELECT * FROM notes WHERE owner = '\" + owner + \"'\", cb);",
    'exports.insert = (text, cb) => db.query("INSERT INTO notes (text) VALUES ($1)", [text], cb);',
    "",
  ].join("\n"),
});

test("a scan that could not follow most routes and calls exits 3 with a warning, not 0 — and says so in --json", () => {
  const json = scan(opaque, "--json");
  assert.equal(json.code, 3, json.stderr);
  const out = JSON.parse(json.stdout);
  assert.deepEqual(out.findings, [], "no findings — which here means blind, not clean");
  assert.equal(out.analysis.complete, false);
  assert.equal(out.analysis.entryPointsTotal, 3);
  assert.equal(out.analysis.entryPointsResolved, 1, "only the inline /health handler resolved");
  assert.equal(out.analysis.unresolved, 2, "both database calls");
  assert.match(out.analysis.reasons.map((r: { reason: string }) => r.reason).join("\n"), /dynamic require\("\.\/" \+ name\)/);
  assert.match(out.analysis.reasons.map((r: { reason: string }) => r.reason).join("\n"), /dynamic require\(process\.env\.NOTES_DAO\)/);
  assert.match(out.analysis.problems.join("\n"), /could not follow 2 of 3 routes/);

  const human = scan(opaque, "--no-color");
  assert.equal(human.code, 3);
  assert.match(human.stdout, /^ {2}Analysis: {7}INCOMPLETE — 1 of 3 routes, 0 of 2 tainted calls followed$/m);
  assert.match(human.stdout, /⚠ INCOMPLETE ANALYSIS — results are NOT a clean bill of health/);
  assert.match(human.stdout, /Not followed \(unsupported code patterns\):\n\s+\d+× dynamic require/);
  assert.match(human.stdout, /Exit code 3\s+\(incomplete analysis\),\s+not 0\./); // the paragraph is word-wrapped
  // The warning is the last thing printed, after the summary and the per-class notes.
  assert.ok(human.stdout.lastIndexOf("INCOMPLETE ANALYSIS") > human.stdout.lastIndexOf("── Summary"));

  for (const mode of ["sqli", "access", "xss"]) assert.equal(scan(opaque, "--mode", mode, "--json").code, 3, `--mode ${mode}`);
});

test("--max-unresolved tunes the threshold: 100 accepts any coverage; a bad value is a usage error", () => {
  const lenient = scan(opaque, "--max-unresolved", "100", "--json");
  assert.equal(lenient.code, 0, lenient.stderr);
  assert.equal(JSON.parse(lenient.stdout).analysis.complete, true);
  assert.doesNotMatch(lenient.stderr, /INCOMPLETE ANALYSIS/);

  const bad = scan(opaque, "--max-unresolved", "lots");
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /--max-unresolved must be a percentage between 0 and 100/);
});

test("a project with no entry point at all is incomplete: nothing was analyzed", () => {
  const dir = project("no-routes", { "lib/math.js": "module.exports = { add: (a, b) => a + b };\n" });
  const run = scan(dir, "--json");
  assert.equal(run.code, 3, run.stderr);
  assert.match(JSON.parse(run.stdout).analysis.problems[0], /no request entry point/);
});

test("assessCoverage: complete when everything was followed; one class's broken traces are not hidden by the others", () => {
  const empty: Coverage = { files: 4, parseErrors: [], entryPoints: 2, registrations: [], followed: [], unresolved: [] };
  const route = (line: number) => ({ file: "app.js", line, call: "app.get", route: `GET /r${line}`, handler: true, unresolved: [] });
  const site = (line: number) => ({ file: "svc.js", line, call: `svc.f${line}` });
  const sqli: Coverage = { ...empty, registrations: [route(1), route(2)], followed: [1, 2, 3, 4, 5, 6, 7, 8, 9].map(site) };
  assert.equal(assessCoverage([{ name: "SQL injection", coverage: sqli }]).complete, true);

  // XSS followed none of its own calls; overall that is 2 of 11 unresolved (18%), under the 20% default.
  const xss: Coverage = { ...empty, unresolved: [10, 11].map((line) => ({ ...site(line), reason: "computed member access x[k]" })) };
  const a = assessCoverage([{ name: "SQL injection", coverage: sqli }, { name: "XSS", coverage: xss }]);
  assert.equal(a.complete, false);
  assert.deepEqual(a.problems, ["XSS: could not follow 2 of 2 tainted calls into project code (100%)"]);
  assert.equal(a.callsFollowed, 9);
  assert.equal(a.unresolved, 2);

  const parse: Coverage = { ...sqli, parseErrors: [{ file: "a.js", line: 1, message: "Expression expected." }, { file: "b.js", line: 3, message: "'}' expected." }] };
  assert.match(assessCoverage([{ name: "SQL injection", coverage: parse }]).problems[0], /2 of 4 files failed to parse \(50%\)/);
});
