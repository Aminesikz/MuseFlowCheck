// SQL injection across database libraries: Stage 1 recognizes the execute calls of the common drivers (gated on SQL
// text for generic method names), names the driver of each sink, and the judge prompt asks for that driver's binding
// style. Offline — no API calls; the test-cases/ files are traced, never run.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { buildJudgePrompt, groupBySink, traceEntry, traceProject, Tracer, type TraceResult } from "../src/engine/crossfile/index.js";
import { buildSqliPrompt } from "../src/engine/prompt.js";

const cases = fileURLToPath(new URL("../test-cases", import.meta.url));
const traceCase = (file: string) => traceEntry(path.join(cases, file), cases);
/** Paths whose input reaches the SQL text, as "source line → sink line (driver)". */
const sqlText = (t: TraceResult) => t.paths.filter((p) => p.sqlText).map((p) => `${p.hops[0].line} → ${p.hops.at(-1)!.line} (${p.driver ?? "?"})`);

test("concatenated SQL in MySQL, SQLite and SQL Server code reaches Stage 1, with the driver named", () => {
  assert.deepEqual(sqlText(traceCase("mysql2-concat.js")), ["8 → 10 (mysql2)"]); // pool.execute
  assert.deepEqual(sqlText(traceCase("sqlite-prepare.js")), ["8 → 9 (better-sqlite3)"]); // db.prepare(<concatenated>).all()
  assert.deepEqual(sqlText(traceCase("mssql-request.js")), ["10 → 10 (mssql)"]); // request.query(<concatenated>)
  assert.deepEqual(sqlText(traceCase("knex-raw-join.js")), ["7 → 9 (knex)", "8 → 9 (knex)"]); // knex.raw, two sources
});

test("parameterized queries in other dialects never reach the judge as SQL text", () => {
  for (const file of ["mysql2-safe.js", "mssql-safe.js", "sqlite3-safe.js"]) {
    const t = traceCase(file);
    assert.deepEqual(sqlText(t), [], `${file}: input reaches only bound parameters`);
    assert.ok(t.paths.every((p) => !p.sqlText));
  }
  // mysql2 ? with an array, sqlite3 ? and $name: recorded as bound parameters, which are not sent to the model.
  assert.equal(traceCase("mysql2-safe.js").paths.length, 2);
  assert.equal(traceCase("sqlite3-safe.js").paths.length, 2);
});

const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-dialects-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

test("generic method names are sinks only when their first argument is SQL text", () => {
  const dir = path.join(tmp, "generic");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    path.join(dir, "routes.js"),
    `const express = require('express');
const lru = require('lru-cache');
const Database = require('better-sqlite3');
const db = new Database('x.db');
const router = express.Router();
const cache = new lru.LRUCache({ max: 10 });
router.get('/a', async (req, res) => {
  const hit = cache.get(req.query.key);
  const parts = /^(\\w+)-(\\d+)$/.exec(req.query.code);
  const all = await Promise.all([req.query.one, req.query.two]);
  const label = 'select ' + req.query.label;
  const found = document.querySelector('select' + req.query.selector);
  const rows = db.prepare('SELECT * FROM t WHERE c = ' + req.query.control).all();
  res.json({ hit, parts, all, label, found, rows, ran: cache.run('cleanup ' + req.query.task) });
});
module.exports = router;
`,
  );
  const t = traceProject(dir);
  // Only the control — a prepare() of SQL text — is a sink; map.get, regex.exec, Promise.all, querySelector and
  // cache.run on non-SQL text are not.
  assert.deepEqual(t.paths.map((p) => `${p.origin.split(":").slice(1).join(":")} → ${p.hops.at(-1)!.code.slice(0, 20)}`), ["13:req.query → db.prepare('SELECT *"]);
});

test("the widened sinks apply to SQL injection only: a default tracer (XSS, access control) keeps query/execute", () => {
  const narrow = traceProject(cases, new Tracer(cases));
  const wide = traceProject(cases);
  const sinks = (t: TraceResult) => [...new Set(t.paths.map((p) => `${p.hops.at(-1)!.file}:${p.hops.at(-1)!.line}`))].sort();
  for (const s of ["sqlite-prepare.js:9", "knex-raw-join.js:9", "sqlite3-safe.js:8", "sqlite3-safe.js:18"]) {
    assert.ok(sinks(wide).includes(s), `wide: ${s}`);
    assert.ok(!sinks(narrow).includes(s), `narrow: ${s}`);
  }
  assert.ok(narrow.paths.every((p) => p.driver === undefined), "no driver lookup without the option");
});

test("the judge prompt names the driver and its binding style, so the patch uses the right placeholders", () => {
  const prompt = (file: string) => buildJudgePrompt(groupBySink(traceCase(file).paths.filter((p) => p.sqlText))[0]);
  assert.match(prompt("mysql2-concat.js"), /DATABASE LIBRARY \(read from the code of the SQL call\): mysql2\. MySQL — \? placeholders with the values in an array/);
  assert.match(prompt("sqlite-prepare.js"), /: better-sqlite3\. SQLite — \? placeholders/);
  assert.match(prompt("mssql-request.js"), /: mssql\. SQL Server — @name parameters declared on the request: request\.input\(/);
  assert.match(prompt("knex-raw-join.js"), /: knex\. knex — \? placeholders with a bindings array/);
  assert.match(prompt("sequelize-template.ts"), /: sequelize\. Sequelize — replacements/);
  assert.match(prompt("mysql2-concat.js"), /The suggestedPatch must use exactly this binding style\./);
  assert.match(prompt("mysql2-concat.js"), /"suggestedPatch": string {3}\/\/ corrected code .* using the DATABASE LIBRARY's parameter binding above/);
});

test("Postgres code is still traced the same way, with pg named and $1 binding", () => {
  const t = traceProject(fileURLToPath(new URL("./project-scan", import.meta.url)));
  const pgPaths = t.paths.filter((p) => p.sqlText);
  assert.ok(pgPaths.length > 0);
  assert.ok(pgPaths.every((p) => p.driver === "pg"), JSON.stringify(pgPaths.map((p) => p.driver)));
  assert.match(buildJudgePrompt(groupBySink(pgPaths)[0]), /: pg\. PostgreSQL — numbered placeholders \$1, \$2/);
});

test("the single-file prompt asks for the binding style of the library the file uses", () => {
  const p = buildSqliPrompt("PLACEHOLDER", "");
  assert.match(p, /BINDING — the patch must bind values the way the library the code uses does, never with another library's placeholders/);
  assert.match(p, /SQL Server @name declared with request\.input/);
});
