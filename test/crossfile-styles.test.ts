// Offline tests for import/call resolution styles in the cross-file tracer — no API calls.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { traceEntry, type CandidatePath, type TraceResult } from "../src/engine/crossfile/index.js";

function load(project: string, entry: string): TraceResult {
  const root = fileURLToPath(new URL(`./${project}`, import.meta.url));
  return traceEntry(`${root}/${entry}`, root);
}

const hops = (p: CandidatePath) => p.hops.map((h) => `${h.kind} ${h.file}:${h.line}`);
const fromLine = (trace: TraceResult, file: string, line: number) =>
  trace.paths.filter((p) => p.hops[0].file === file && p.hops[0].line === line);

// ---- CommonJS ---------------------------------------------------------------------------------

const cjs = load("crossfile-styles", "routes/items.js");

test("cjs: handlers include ones defined in other files and referenced at route registration", () => {
  assert.equal(cjs.handlers, 11);
  assert.equal(fromLine(cjs, "controllers/items.js", 4).length, 1);
});

test("cjs: destructured require through a barrel index.js", () => {
  const [p] = fromLine(cjs, "routes/items.js", 16);
  assert.deepEqual(hops(p), [
    "source routes/items.js:16",
    "call routes/items.js:16",
    "param services/items.js:3",
    "call services/items.js:4",
    "param db/repo.js:4",
    "sink db/repo.js:5",
  ]);
  assert.ok(p.sqlText);
});

test("cjs: aliased namespace require, spread re-export, exports.x arrow, destructured method", () => {
  const [p] = fromLine(cjs, "routes/items.js", 20);
  assert.equal(p.sqlText, false); // reaches only a bound parameter
  assert.deepEqual(hops(p).slice(-4), ["param services/counts.js:3", "call services/counts.js:3", "param db/repo.js:7", "sink db/repo.js:8"]);
});

test("cjs: exported class instance, destructured parameter mapped by key, this.method()", () => {
  const [p] = fromLine(cjs, "routes/items.js", 25);
  assert.deepEqual(hops(p), [
    "source routes/items.js:25",
    "call routes/items.js:25",
    "param services/catalog.js:4",
    "call services/catalog.js:5",
    "param services/catalog.js:8",
    "call services/catalog.js:9",
    "param db/repo.js:4",
    "sink db/repo.js:5",
  ]);
  assert.match(p.hops[2].code, /\[param name\]$/);
  // `limit: 10` is a literal, so no path carries taint through `limit`.
  assert.ok(p.hops.every((h) => !h.code.includes("[param limit]")));
});

test("cjs: method on an object returned by a single-return factory", () => {
  const [p] = fromLine(cjs, "routes/items.js", 39);
  assert.deepEqual(hops(p), ["source routes/items.js:39", "call routes/items.js:39", "param services/audit.js:5", "sink services/audit.js:6"]);
  assert.equal(p.hops[2].fn.name, "createAudit().record");
});

test("cjs: function-expression property of module.exports object", () => {
  const [p] = fromLine(cjs, "controllers/items.js", 4);
  assert.deepEqual(hops(p).slice(-2), ["param db/repo.js:10", "sink db/repo.js:11"]);
});

test("cjs: constructor-injected dependency resolved from the `new` site", () => {
  const [p] = fromLine(cjs, "routes/items.js", 44);
  assert.deepEqual(hops(p), [
    "source routes/items.js:44",
    "call routes/items.js:44",
    "param services/reporter.js:6",
    "call services/reporter.js:7",
    "param db/repo.js:10",
    "sink db/repo.js:11",
  ]);
});

test("cjs: injection through super(...) into a base class; require() of a module exporting a class", () => {
  const [p] = fromLine(cjs, "routes/items.js", 48);
  assert.deepEqual(hops(p).slice(2), ["param services/base.js:6", "call services/base.js:7", "param db/repo.js:10", "sink db/repo.js:11"]);
});

test("cjs: class-field arrow handler registered by reference keeps its `this` binding", () => {
  const [p] = fromLine(cjs, "controllers/orders.js", 9);
  assert.deepEqual(hops(p), ["source controllers/orders.js:9", "call controllers/orders.js:9", "param db/repo.js:10", "sink db/repo.js:11"]);
});

test("cjs: unresolved edges are surfaced with the style that broke them", () => {
  const reasons = cjs.unresolved.map((u) => `${u.file}:${u.line} ${u.call} — ${u.reason}`);
  assert.deepEqual(reasons, [
    "routes/items.js:29 plugin.run — dynamic require(process.env.ITEMS_PLUGIN) — module path is computed at runtime",
    "routes/items.js:33 svc.removed — services/index.js has no export 'removed'",
    "routes/items.js:52 new Search — tainted constructor argument — taint stored in instance fields is not tracked",
  ]);
});

test("cjs: tainted calls leaving the project are listed, not dropped", () => {
  assert.ok(cjs.external.length > 0);
  assert.ok(cjs.external.every((e) => e.call === "res.json" && e.target === "parameter 'res'"));
});

// ---- ES modules / TypeScript ------------------------------------------------------------------

const esm = load("crossfile-esm", "routes/reports.ts");

test("esm: aliased named import re-exported from a barrel (.js specifier → .ts file)", () => {
  const [p] = fromLine(esm, "routes/reports.ts", 10);
  assert.deepEqual(hops(p), ["source routes/reports.ts:10", "call routes/reports.ts:10", "param db/users.ts:3", "sink db/users.ts:4"]);
});

test("esm: default import re-exported as `export { default } from` → object method", () => {
  const [p] = fromLine(esm, "routes/reports.ts", 14);
  assert.equal(p.sqlText, false);
  assert.deepEqual(hops(p).slice(-2), ["param db/orders.ts:4", "sink db/orders.ts:5"]);
});

test("esm: namespace import through `export * from`", () => {
  const [p] = fromLine(esm, "routes/reports.ts", 18);
  assert.deepEqual(hops(p).slice(2), ["param services/monthly.ts:3", "build services/monthly.ts:4", "sink services/monthly.ts:5"]);
});

test("esm: default-exported function declaration; package-created client is a sink receiver", () => {
  const [p] = fromLine(esm, "routes/reports.ts", 22);
  assert.deepEqual(hops(p).slice(2), ["param services/run.ts:3", "sink services/run.ts:4"]);
});

test("esm: TypeScript parameter properties injected through nested `new` arguments", () => {
  const [p] = fromLine(esm, "routes/reports.ts", 26);
  assert.deepEqual(hops(p).slice(2), [
    "param services/ledger.ts:14",
    "call services/ledger.ts:15",
    "param services/ledger.ts:6",
    "sink services/ledger.ts:7",
  ]);
});

test("esm: nothing unresolved", () => assert.deepEqual(esm.unresolved, []));
