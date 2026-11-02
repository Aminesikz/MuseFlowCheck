// Findings whose suggested fixes rewrite the same handler or function: each patch fixes only its own finding, so
// applied alone it leaves the other bug and applied in turn they conflict. The CLI cards (and the Action) warn and
// group them; the patches are never merged. The CLI case drives the real CLI against a local stand-in model endpoint.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { describeTarget, findingCard, fixGroups, fixTarget, groupOf, makeColors, sharedFixNote } from "../src/report.js";
import type { Finding } from "../src/types/index.js";

// PR 1 of the live Action test: one handler, two findings, and the two patches the model suggested — each rewrites
// the whole handler and fixes only its own bug.
const base: Finding = {
  type: "SQL Injection",
  cwe: "CWE-89",
  severity: "critical",
  file: "routes/search.js",
  sourceLine: 8,
  sinkLine: 9,
  taintPath: ["routes/search.js:8  const q = req.query.q;", `routes/search.js:9  db.query("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'")`],
  explanation: "q is concatenated into the SQL text.",
  suggestedPatch: [
    'router.get("/search", async (req, res) => {',
    "  const q = req.query.q;",
    '  const { rows } = await db.query("SELECT id, name, price FROM products WHERE name LIKE $1", [`%${q}%`]);',
    "  const items = rows.map((r) => `<li>${r.name} — $${r.price}</li>`).join(\"\");",
    "  res.send(`<h1>Results for ${q}</h1><ul>${items}</ul>`);",
    "});",
  ].join("\n"),
  httpRoute: "GET /search",
  confidence: "suspected",
};
const sqli = base;
const xss: Finding = {
  ...base,
  type: "Cross-Site Scripting (Reflected)",
  cwe: "CWE-79",
  severity: "high",
  sinkLine: 11,
  taintPath: [base.taintPath[0], "routes/search.js:11  res.send(`<h1>Results for ${q}</h1><ul>${items}</ul>`);"],
  suggestedPatch: [
    'router.get("/search", async (req, res) => {',
    "  const q = req.query.q;",
    '  const escQ = String(q ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;");',
    `  const { rows } = await db.query("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'");`,
    "  res.send(`<h1>Results for ${escQ}</h1>`);",
    "});",
  ].join("\n"),
};

test("fixTarget: a route-registration patch rewrites the route's handler; a function patch, that function", () => {
  assert.deepEqual(fixTarget(sqli), { kind: "handler", name: "GET /search", file: "routes/search.js" });
  // A router mounted under a prefix: the finding's route names the handler, not the path written in the patch.
  assert.deepEqual(fixTarget({ ...sqli, httpRoute: "GET /api/search" }), { kind: "handler", name: "GET /api/search", file: "routes/search.js" });
  assert.deepEqual(fixTarget({ ...sqli, httpRoute: undefined }), { kind: "handler", name: "GET /search", file: "routes/search.js" });

  const fn: Finding = { ...sqli, taintPath: [...sqli.taintPath, "db/repo.js:4  function find(name)  [param name]"], suggestedPatch: "function find(name) {\n  return db.query('… $1', [name]);\n}" };
  assert.deepEqual(fixTarget(fn), { kind: "function", name: "find", file: "db/repo.js" });
  // A patch that is neither, or names a function the path never declares: placed on the route the input enters.
  assert.deepEqual(fixTarget({ ...sqli, suggestedPatch: "// use a bound parameter" }), { kind: "handler", name: "GET /search", file: "routes/search.js" });
  assert.deepEqual(fixTarget({ ...sqli, suggestedPatch: "function elsewhere() {}" }), { kind: "handler", name: "GET /search", file: "routes/search.js" });
  assert.equal(fixTarget({ ...sqli, httpRoute: undefined, suggestedPatch: "// use a bound parameter" }), undefined);
});

test("fixGroups: findings rewriting the same target are grouped; different targets, or a lone finding, are not", () => {
  const [group] = fixGroups([sqli, xss]);
  assert.deepEqual(group.target, { kind: "handler", name: "GET /search", file: "routes/search.js" });
  assert.deepEqual(group.findings, [sqli, xss]);
  assert.equal(groupOf(xss, [group]), group);

  assert.deepEqual(fixGroups([sqli]), []);
  assert.deepEqual(fixGroups([sqli, { ...xss, httpRoute: "GET /other" }]), [], "another route's handler");
  assert.deepEqual(fixGroups([sqli, { ...xss, file: "routes/other.js" }]), [], "another file");
  // One fix rewrites a helper function, the other the handler: they do not overlap.
  const helper: Finding = { ...sqli, taintPath: [...sqli.taintPath, "db/repo.js:4  function find(name)  [param name]"], suggestedPatch: "function find(name) {}" };
  assert.deepEqual(fixGroups([helper, xss]), []);
  // Two fixes of the same helper do.
  assert.equal(fixGroups([helper, { ...helper, type: "Other", cwe: "CWE-1" }])[0].target.kind, "function");
});

test("sharedFixNote and the CLI card: the other findings by type, CWE and location, and an instruction to combine", () => {
  const [group] = fixGroups([sqli, xss]);
  assert.equal(describeTarget(group.target), "GET /search handler in routes/search.js");
  assert.equal(
    sharedFixNote(sqli, group),
    "The GET /search handler in routes/search.js has 2 findings (also: Cross-Site Scripting (Reflected) (CWE-79) at routes/search.js:11). " +
      "The suggested fixes each rewrite the handler independently — apply them together, not in isolation, or combine them into one fix.",
  );
  assert.match(sharedFixNote(xss, group, (f) => `server/${f}`), /also: SQL Injection \(CWE-89\) at server\/routes\/search\.js:9\)/);

  const card = findingCard(makeColors(false), sqli, 1, 2, 100, group);
  assert.match(card, /^ {2}⚠ Fix together\n {4}The GET \/search handler in routes\/search\.js has 2 findings \(also: Cross-Site Scripting/m);
  assert.ok(card.indexOf("⚠ Fix together") < card.indexOf("Fix — suggested patch"), "the warning sits above the fix");
  assert.doesNotMatch(findingCard(makeColors(false), sqli, 1, 1, 100), /Fix together/, "no warning without a group");
});

// ---- the real CLI --------------------------------------------------------------------------------------

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-shared-"));
const project = path.join(tmp, "app");
cpSync(fileURLToPath(new URL("./action-shared-handler", import.meta.url)), project, { recursive: true });

let model: http.Server;
let env: NodeJS.ProcessEnv;
before(async () => {
  // Every judge prompt gets one high finding back; the XSS judge sets its own type and CWE.
  model = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const text = JSON.stringify([{ type: "SQL Injection", cwe: "CWE-89", severity: "high", path: 1, explanation: "e", suggestedPatch: 'router.get("/search", async (req, res) => {\n});' }]);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ id: "r", object: "response", status: "completed", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] }] }));
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", r));
  env = { ...process.env, META_API_KEY: "offline-test", META_BASE_URL: `http://127.0.0.1:${(model.address() as AddressInfo).port}`, META_MODEL: "fake" };
});
after(() => {
  model.close();
  rmSync(tmp, { recursive: true, force: true });
});

test("cli: both findings in PR 1's handler carry the warning, and a closing line says which to fix together", async () => {
  const out = await new Promise<string>((resolve) => execFile(tsx, [cli, "scan", project, "--no-color"], { cwd: tmp, env }, (_err, stdout) => resolve(stdout)));
  const cards = out.split(/^─{20,}$/m).filter((c) => /\[HIGH\]/.test(c));
  assert.equal(cards.length, 2, out);
  const flat = cards.map((c) => c.replace(/\s+/g, " ")); // the note is word-wrapped to the card width
  assert.match(flat[0], /SQL Injection · CWE-89 .* ⚠ Fix together The GET \/search handler in routes\/search\.js has 2 findings \(also: Cross-Site Scripting \(Reflected\) \(CWE-79\) at routes\/search\.js:11\)\. .* apply them together, not in isolation, or combine them into one fix\. Fix — suggested patch/);
  assert.match(flat[1], /Cross-Site Scripting \(Reflected\) · CWE-79 .* ⚠ Fix together The GET \/search handler in routes\/search\.js has 2 findings \(also: SQL Injection \(CWE-89\) at routes\/search\.js:9\)\. .* Fix — suggested patch/);
  assert.match(out, /^⚠ 2 findings share the GET \/search handler in routes\/search\.js — combine their fixes: #1 SQL Injection \(CWE-89\), #2 Cross-Site Scripting \(Reflected\) \(CWE-79\)$/m);
});
