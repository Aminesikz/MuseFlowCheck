// Offline tests for directory scanning: file discovery, entry-point discovery, dedupe, judge cache — no API calls.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { discoverFiles, groupBySink, groupSignature, judgeTrace, traceProject, type CandidatePath } from "../src/engine/crossfile/index.js";
import type { Finding } from "../src/types/index.js";

const root = fileURLToPath(new URL("./project-scan", import.meta.url));
const trace = traceProject(root);
const hops = (p: CandidatePath) => p.hops.map((h) => `${h.kind} ${h.file}:${h.line}`);

test("entry points: registrations (by reference, wrapped, bound, Koa) and a convention-called handler", () => {
  const entries = trace.entryPoints.map((e) => `${e.route ?? "-"} ${e.file}:${e.line} ${e.registeredAt ?? ""}`.trim());
  assert.deepEqual(entries, [
    "GET /search routes/search.js:3 app.js:11", // registered twice; listed once
    "GET /reports/:kind controllers/reports.js:6 app.js:13", // asyncHandler(reports.show.bind(reports))
    "POST /notes app.js:17",
    "- pages/api/user.js:3",
  ]);
  assert.equal(trace.files, 8);
});

test("a project object's own get() is not a route, and services reached from handlers are not entry points", () => {
  assert.ok(!trace.entryPoints.some((e) => e.file === "lib/cache.js" || e.file === "services/finder.js"));
});

test("whole request object passed on: the path starts at the handler's call", () => {
  const p = trace.paths.find((c) => c.sqlText && c.hops[0].file === "routes/search.js")!;
  assert.deepEqual(hops(p), [
    "call routes/search.js:4",
    "param services/finder.js:3",
    "source services/finder.js:4",
    "call services/finder.js:5",
    "param db.js:6",
    "sink db.js:6",
  ]);
  assert.match(p.hops[1].code, /\[param request = request\]$/);
});

test("constructor-injected controller registered through a wrapper and bind()", () => {
  const p = trace.paths.find((c) => c.sqlText && c.hops[0].file === "controllers/reports.js")!;
  assert.deepEqual(hops(p), ["source controllers/reports.js:7", "call controllers/reports.js:7", "param db.js:6", "sink db.js:6"]);
});

test("Koa ctx.request.body and convention-called handlers reach SQL only as bound parameters", () => {
  const bound = trace.paths.filter((p) => !p.sqlText).map((p) => `${p.hops[0].file}:${p.hops[0].line}`);
  assert.deepEqual(bound, ["app.js:18", "pages/api/user.js:4"]);
});

test("paths from every entry point into one SQL call form one judge group", () => {
  const groups = groupBySink(trace.paths);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].paths.length, 2);
  assert.deepEqual(trace.unresolved, []);
});

test("judge cache: a group already judged is not sent to the model again", async () => {
  const [group] = groupBySink(trace.paths);
  const cached = { type: "SQL Injection", severity: "critical" } as Finding;
  const result = await judgeTrace(trace, new Map([[groupSignature(group), Promise.resolve(cached)]]));
  assert.equal(result.calls, 0);
  assert.equal(result.sinks, 1);
  assert.deepEqual(result.findings, [cached]);
});

test("a failed judgment is collected, not thrown, so the rest of the scan completes", async () => {
  const [group] = groupBySink(trace.paths);
  const result = await judgeTrace(trace, new Map([[groupSignature(group), Promise.reject(new Error("boom"))]]));
  assert.equal(result.findings.length, 0);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0].sink, /^db\.js:6/);
});

// ---- file discovery ---------------------------------------------------------------------------

const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-scan-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function write(rel: string, text = "module.exports = {};\n"): void {
  mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true });
  writeFileSync(path.join(tmp, rel), text);
}

test("discovery honors .gitignore (root and nested) and skips dependencies, build output and tests", () => {
  write(".gitignore", "generated/\nlegacy.js\n");
  for (const f of [
    "src/app.js",
    "src/nested/kept.ts",
    "src/nested/secret-route.js",
    "generated/client.js",
    "legacy.js",
    "node_modules/pkg/index.js",
    "dist/app.js",
    "build/app.js",
    "coverage/lcov.js",
    "app.test.js",
    "src/routes.spec.ts",
    "test/helper.js",
    "src/__tests__/a.js",
    "types.d.ts",
    "vendor.min.js",
    ".hidden/x.js",
    "README.md",
  ]) {
    write(f);
  }
  write("src/nested/.gitignore", "secret-route.js\n");
  assert.deepEqual(
    discoverFiles(tmp).map((f) => path.relative(tmp, f)),
    ["src/app.js", "src/nested/kept.ts"].map((f) => f.split("/").join(path.sep)),
  );
});

test("cli: scan <dir> --json prints only the Finding[] on stdout, and exits 0 when nothing reaches SQL text", () => {
  const project = path.join(tmp, "safe");
  mkdirSync(path.join(project, "routes"), { recursive: true });
  writeFileSync(
    path.join(project, "routes", "users.js"),
    "const db = require('pg');\nmodule.exports = (router) => router.get('/u', (req, res) => db.query('SELECT 1 WHERE id = $1', [req.query.id]));\n",
  );
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
  // An unreachable API endpoint: a bug that tried to call the model would fail here instead of reaching it.
  const env = { ...process.env, META_API_KEY: "offline-test", META_BASE_URL: "http://127.0.0.1:9", META_MODEL: "none" };
  const run = spawnSync(tsx, [cli, "scan", project, "--json"], { cwd: tmp, env, encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), []);
  assert.match(run.stderr, /Files scanned: {2}1/);
  assert.match(run.stderr, /1 path\(s\) reach SQL only as bound parameters/);
});
