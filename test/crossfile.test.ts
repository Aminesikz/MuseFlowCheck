// Offline tests for the cross-file tracer (Stage 1) and judge parsing (Stage 2) — no API calls.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildJudgePrompt, groupBySink, traceEntry } from "../src/engine/crossfile/index.js";
import { parseJudgment } from "../src/engine/crossfile/judge.js";
import { FindingParseError } from "../src/engine/parse.js";

const root = fileURLToPath(new URL("./crossfile-project", import.meta.url));
const trace = traceEntry(`${root}/routes/orders.js`, root);
const sqlText = trace.paths.filter((p) => p.sqlText);
const bound = trace.paths.filter((p) => !p.sqlText);

test("finds both request handlers", () => assert.equal(trace.handlers, 2));
test("no unresolved calls", () => assert.deepEqual(trace.unresolved, []));

test("traces route → service → db into SQL text", () => {
  assert.equal(sqlText.length, 1);
  const hops = sqlText[0].hops.map((h) => `${h.kind} ${h.file}:${h.line}`);
  assert.deepEqual(hops, [
    "source routes/orders.js:7",
    "call routes/orders.js:8",
    "param services/orderService.js:3",
    "propagate services/orderService.js:4",
    "call services/orderService.js:5",
    "param db/orders.js:3",
    "build db/orders.js:4",
    "sink db/orders.js:5",
  ]);
});

test("bound parameters are classified, not sent as SQL-text paths", () => {
  assert.equal(bound.length, 1);
  assert.equal(bound[0].hops[0].kind, "source");
  assert.equal(bound[0].hops.at(-1)!.line, 9);
});

test("inline request reads show the whole enclosing statement", () => {
  const source = bound[0].hops[0];
  assert.equal(source.line, 12);
  assert.equal(source.code, "res.json(await orderService.getOrder(req.params.id));");
});

test("judge prompt includes paths and real-line code slices from every file", () => {
  const [group] = groupBySink(trace.paths);
  const prompt = buildJudgePrompt(group);
  assert.match(prompt, /Path 1:/);
  assert.doesNotMatch(prompt, /Path 0:/);
  assert.match(prompt, /Middleware and route registration are not shown/);
  for (const file of ["routes/orders.js", "services/orderService.js", "db/orders.js"]) assert.match(prompt, new RegExp(`=== ${file}`));
  assert.match(prompt, / {3}4 \| {3}const sql = `SELECT/);
  assert.match(prompt, /=== db\/orders\.js — exports\.search \(lines 3–6\)/);
  assert.match(prompt, /\[param\] services\/orderService\.js:3 {2}searchOrders = async \(text\)/);
});

test("judgment fills locations and taintPath from the trace", () => {
  const [group] = groupBySink(trace.paths);
  const raw = '```json\n[{"type":"SQL Injection","cwe":"CWE-89","severity":"Critical","path":1,"explanation":"e","suggestedPatch":"p","sinkLine":999}]\n```';
  const f = parseJudgment(raw, group)!;
  assert.equal(f.file, "routes/orders.js");
  assert.equal(f.sourceLine, 7);
  assert.equal(f.sinkFile, "db/orders.js");
  assert.equal(f.sinkLine, 5);
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "suspected");
  assert.equal(f.taintPath.length, 8);
});

test("path number is 1-based; out-of-range or missing falls back to path 1", () => {
  const [group] = groupBySink(trace.paths);
  const twoPaths = { ...group, paths: [group.paths[0], { ...group.paths[0], hops: group.paths[0].hops.slice(1) }] };
  const judge = (path: unknown) =>
    parseJudgment(JSON.stringify([{ type: "SQL Injection", cwe: "CWE-89", severity: "high", path, explanation: "e", suggestedPatch: "p" }]), twoPaths)!;
  assert.equal(judge(2).taintPath.length, 7);
  assert.equal(judge(1).taintPath.length, 8);
  assert.equal(judge(0).taintPath.length, 8);
  assert.equal(judge(9).taintPath.length, 8);
  assert.equal(judge(undefined).taintPath.length, 8);
});

test("empty judgment means not exploitable", () => {
  assert.equal(parseJudgment("[]", groupBySink(trace.paths)[0]), null);
});
test("bad judgment keeps the raw response", () => {
  assert.throws(() => parseJudgment('[{"severity":"urgent"}]', groupBySink(trace.paths)[0]), FindingParseError);
});
