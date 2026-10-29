// Offline tests for XSS analysis: Stage 1 tracing to HTML output, encoding discrimination, and judge parsing — no API calls.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildXssPrompt, groupXssBySink, judgeXss, parseXssJudgment, traceXssProject, type XssPath } from "../src/engine/xss/index.js";
import { FindingParseError } from "../src/engine/parse.js";

const root = fileURLToPath(new URL("./xss-project", import.meta.url));
const trace = traceXssProject(root);
const raw = trace.xss.filter((p) => !p.encoded);
const encoded = trace.xss.filter((p) => p.encoded);
const at = (p: XssPath) => `${p.hops.at(-1)!.file}:${p.hops.at(-1)!.line}`;
const hops = (p: XssPath) => p.hops.map((h) => `${h.kind} ${h.file}:${h.line}`);

test("raw request input reaching HTML output is a candidate, wherever it is built", () => {
  assert.deepEqual(
    raw.map((p) => `${p.route} ${at(p)} ${p.context}`),
    [
      "GET /echo app.js:8 markup", // concatenated into markup in the handler
      "GET /raw app.js:9 response", // written to the response as-is
      "GET /library/find templates/results.js:10 markup", // a plain-text helper's result placed into markup
      "GET /library/find templates/results.js:13 markup", // a helper named like an encoder that only trims
    ],
  );
});

test("values passing an HTML-encoding step are listed as encoded, not as candidates", () => {
  assert.deepEqual(
    encoded.map((p) => `${at(p)} ${p.encoder}`),
    [
      "templates/results.js:11 .replace(/</g, …) at templates/encode.js:4", // project helper: recognized by what it does
      "templates/results.js:12 he.encode (package 'he')",
    ],
  );
});

test("numbers, JSON responses and database rows are not reflected markup", () => {
  const sinks = trace.xss.map(at);
  assert.ok(!sinks.includes("app.js:10"), "Number() output cannot carry markup");
  assert.ok(!sinks.includes("app.js:11"), "an object is sent as JSON");
  assert.ok(!sinks.includes("templates/results.js:14"), "book names come from the database, not this request");
});

test("traces route → service → template across files, through a plain-text helper", () => {
  const p = raw.find((c) => at(c) === "templates/results.js:10")!;
  assert.deepEqual(hops(p), [
    "source routes/catalog.js:7",
    "call routes/catalog.js:7",
    "param services/catalog.js:4",
    "propagate services/catalog.js:6", // after a callback (.filter) earlier in the function body
    "call services/catalog.js:7",
    "param templates/results.js:8",
    "call templates/results.js:10",
    "param templates/results.js:4", // the helper whose return value carries the input
    "sink templates/results.js:10",
  ]);
  assert.equal(p.origin, "routes/catalog.js:7:req.query.title");
  assert.match(p.hops.at(-1)!.code, /<h2>\$\{summary\(title\)\}<\/h2>/);
});

test("the same input is raw at one output and encoded at another", () => {
  const title = trace.xss.filter((p) => p.origin === "routes/catalog.js:7:req.query.title");
  assert.deepEqual(title.map((p) => `${at(p)} ${p.encoded ? "encoded" : "raw"}`), [
    "templates/results.js:10 raw",
    "templates/results.js:11 encoded",
  ]);
});

test("SQL execution is not an XSS sink", () => {
  assert.deepEqual(trace.paths, []);
  assert.deepEqual(trace.unresolved, []);
});

test("only raw outputs are grouped for the model, each with the encoded outputs of the same input for contrast", () => {
  const groups = groupXssBySink(trace.xss);
  assert.deepEqual(groups.map((g) => `${g.sink.file}:${g.sink.line}`), ["app.js:8", "app.js:9", "templates/results.js:10", "templates/results.js:13"]);
  const heading = groups.find((g) => g.sink.line === 10)!;
  assert.deepEqual(heading.contrast.map(at), ["templates/results.js:11"]);
});

test("prompt asks about encoding on the way to this output, with paths, contrast, imports and code", () => {
  const group = groupXssBySink(trace.xss).find((g) => g.sink.line === 10)!;
  const prompt = buildXssPrompt(group);
  assert.match(prompt, /ON THE WAY TO THIS OUTPUT/);
  assert.match(prompt, /Encoding applied to a DIFFERENT output of the same value does not protect this one/);
  assert.match(prompt, /Path 1:\n {2}1\. \[source\] routes\/catalog\.js:7/);
  assert.match(prompt, /NOT under review[^\n]*\n {2}- templates\/results\.js:11 {2}<input name="title" value="\$\{encode\(title\)\}">/);
  assert.match(prompt, /IMPORTS OF templates\/results\.js\n {2}const he = require\('he'\);\n {2}const \{ encode, escapeText \} = require\('\.\/encode'\);/);
  assert.match(prompt, /=== templates\/results\.js — summary \(lines 4–6\) ===/);
  assert.match(prompt, /"type": "Cross-Site Scripting \(Reflected\)"/);
  assert.match(prompt, /does not apply merely because the vulnerable page is public/);
  assert.doesNotMatch(prompt, /Path 2:/);
});

test("judgment: locations, taintPath and route come from the trace; type and CWE are fixed", () => {
  const group = groupXssBySink(trace.xss).find((g) => g.sink.line === 10)!;
  const reply = '```json\n[{"type":"XSS","cwe":"79","severity":"High","path":1,"explanation":"e","suggestedPatch":"p","sinkLine":1}]\n```';
  const f = parseXssJudgment(reply, group)!;
  assert.equal(f.type, "Cross-Site Scripting (Reflected)");
  assert.equal(f.cwe, "CWE-79");
  assert.equal(f.severity, "high");
  assert.equal(f.file, "routes/catalog.js");
  assert.equal(f.sourceLine, 7);
  assert.equal(f.sinkFile, "templates/results.js");
  assert.equal(f.sinkLine, 10);
  assert.equal(f.httpRoute, "GET /library/find");
  assert.equal(f.confidence, "suspected");
  assert.equal(f.taintPath.at(-1), "templates/results.js:10  <h2>${summary(title)}</h2>");
});

test("judgment: [] means not exploitable; a malformed reply is a parse error", () => {
  const [group] = groupXssBySink(trace.xss);
  assert.equal(parseXssJudgment("[]", group), null);
  assert.throws(() => parseXssJudgment('[{"severity":"high"}]', group), FindingParseError);
});

test("Stage 2 sends each raw output once and never an encoded one", async () => {
  const asked: string[] = [];
  const result = await judgeXss(trace, async (g) => {
    asked.push(`${g.sink.file}:${g.sink.line}`);
    return null;
  });
  assert.deepEqual(asked.sort(), ["app.js:8", "app.js:9", "templates/results.js:10", "templates/results.js:13"]);
  assert.equal(result.calls, 4);
  assert.deepEqual(result.findings, []);
});
