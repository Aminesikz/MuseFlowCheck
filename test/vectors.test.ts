// Several request inputs into one sink: still one finding, with every exploitable input as a vector, named in the
// explanation and closed by the patch. Offline: prompts and parsing run on the fixture's Stage 1 output with canned
// judge replies, and patches are checked by re-running Stage 1 on a patched copy. A sink one input reaches is
// unchanged: no extra prompt text and no `vectors` field.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { accessSeverity, assembleAccessContext, buildAccessPrompt, candidates, type AccessRoute } from "../src/engine/access/index.js";
import { parseAccessJudgment } from "../src/engine/access/judge.js";
import { buildJudgePrompt, groupBySink, traceProject } from "../src/engine/crossfile/index.js";
import { parseJudgment } from "../src/engine/crossfile/judge.js";
import { checkPatchVectors, onlyLengthAt } from "../src/engine/vector-check.js";
import type { Hop } from "../src/engine/crossfile/index.js";
import { buildXssPrompt, groupXssBySink, parseXssJudgment, traceXssProject } from "../src/engine/xss/index.js";
import { findingCard, makeColors } from "../src/report.js";
import type { Finding } from "../src/types/index.js";

const root = fileURLToPath(new URL("./vectors-project", import.meta.url));

const sqliGroups = groupBySink(traceProject(root).paths);
const sqliAt = (line: number) => sqliGroups.find((g) => g.sink.file === "db/notes.js" && g.sink.line === line)!;
const twoParams = sqliAt(9); // teamId and status concatenated into one statement
const oneParam = sqliAt(15);

const xssGroups = groupXssBySink(traceXssProject(root).xss);
const xssAt = (line: number) => xssGroups.find((g) => g.sink.file === "routes/pages.js" && g.sink.line === line)!;
const twoOutputs = xssAt(7); // first and last into one response
const oneOutput = xssAt(12);

const ctx = assembleAccessContext(root);
const routeAt = (p: string): AccessRoute => candidates(ctx).find((r) => r.path === p)!;

/** A judge reply: one finding object with the given fields. */
const reply = (fields: Record<string, unknown>) => JSON.stringify([{ type: "T", cwe: "C", severity: "critical", explanation: "e", suggestedPatch: "p", ...fields }]);
const sqliReply = (fields: Record<string, unknown>) => reply({ type: "SQL Injection", cwe: "CWE-89", ...fields });
const withoutVectors = (f: Finding | null) => {
  const { vectors: _, ...rest } = f!;
  return rest;
};

// ---- prompts -------------------------------------------------------------------------------------------------------

test("SQLi: two parameters into one query are listed as inputs, with the vectors field and the bind-all requirement", () => {
  const prompt = buildJudgePrompt(twoParams, root);
  assert.match(prompt, /SEVERAL INPUTS — Stage 1 traced 2 different request inputs into this SQL execution call:\n- teamId, entering at routes\/notes\.js:7 \(Path 1\)\n- status, entering at routes\/notes\.js:7 \(Path 2\)/);
  assert.match(prompt, /They are ONE vulnerability with several vectors: report one finding, not one per input\./);
  assert.match(prompt, /The suggestedPatch must bind the value as a query parameter \(or neutralize it as listed above\) for every input in "vectors", not only the one in "path"/);
  assert.match(prompt, /"severity": "critical" \| "high" \| "medium" \| "low",\n {2}"vectors": number\[\],/);
});

test("XSS: two inputs into one output are listed, with the encode-all requirement", () => {
  const prompt = buildXssPrompt(twoOutputs);
  assert.match(prompt, /traced 2 different request inputs into this output:\n- req\.query\.first, entering at routes\/pages\.js:7 \(Path 1\)\n- req\.query\.last, entering at routes\/pages\.js:7 \(Path 2\)/);
  assert.match(prompt, /must HTML-encode the value where it enters the markup for every input in "vectors"/);
  assert.match(prompt, /"vectors": number\[\]/);
});

test("access control: two identifiers into the same table are listed, with the check-all requirement", () => {
  const prompt = buildAccessPrompt(ctx, routeAt("/notes/:id/compare"));
  assert.match(prompt, /traced 2 different request inputs into this access:\n- params\.id, entering at routes\/notes\.js:21 \(Path 1\)\n- query\.otherId, entering at routes\/notes\.js:22 \(Path 2\)/);
  assert.match(prompt, /must check the record's owner against the caller's identity for every input in "vectors"/);
});

test("access control: identifiers into different tables are separate accesses, never vectors of one", () => {
  const route = routeAt("/notes/:id/with-team");
  assert.deepEqual(route.accesses.map((a) => `${a.location}.${a.field} → ${a.tables.join()}`), ["params.id → notes", "query.teamId → teams"]);
  assert.doesNotMatch(buildAccessPrompt(ctx, route), /SEVERAL INPUTS|"vectors"/);
  // Even if the judge lists both, they are not merged into one finding's vectors.
  const f = parseAccessJudgment(reply({ path: 1, vectors: [1, 2] }), route, ctx);
  assert.equal(f!.vectors, undefined);
});

test("a sink one input reaches gets no vectors block and no vectors field, in every class", () => {
  for (const prompt of [buildJudgePrompt(oneParam, root), buildXssPrompt(oneOutput), buildAccessPrompt(ctx, routeAt("/notes/:id"))]) {
    assert.doesNotMatch(prompt, /SEVERAL INPUTS|"vectors"/);
  }
});

// ---- parsing ------------------------------------------------------------------------------------------------------

test("SQLi: one finding carries both vectors, the chosen path first; the rest of the finding is unchanged", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), twoParams)!;
  assert.deepEqual(f.vectors!.map((v) => `${v.input} ${v.file}:${v.line} ${v.httpRoute}`), ["teamId routes/notes.js:7 GET /notes", "status routes/notes.js:7 GET /notes"]);
  assert.deepEqual(f.vectors![0].taintPath, f.taintPath);
  assert.ok(f.vectors![1].taintPath.some((h) => h.startsWith("db/notes.js:7 ")), "status's own path, through its concatenation");
  // Enriching only adds the field: severity, locations, taintPath and the rest match a reply without "vectors".
  assert.deepEqual(withoutVectors(f), parseJudgment(sqliReply({ path: 1 }), twoParams));
});

test("SQLi: the chosen path decides which vector is first and what taintPath shows", () => {
  const f = parseJudgment(sqliReply({ path: 2, vectors: [1, 2] }), twoParams)!;
  assert.deepEqual(f.vectors!.map((v) => v.input), ["status", "teamId"]);
  assert.deepEqual(f.vectors![0].taintPath, f.taintPath);
});

test("no vectors field unless the judge names two or more inputs; bad numbers are ignored", () => {
  for (const vectors of [undefined, [1], [1, 1], [0, 9, "2", 1.5], "1,2"]) {
    const f = parseJudgment(sqliReply({ path: 1, ...(vectors !== undefined ? { vectors } : {}) }), twoParams);
    assert.equal(f!.vectors, undefined, JSON.stringify(vectors));
  }
  // The chosen path's input always counts: "path" 1 with "vectors" [2] is both inputs.
  assert.deepEqual(parseJudgment(sqliReply({ path: 1, vectors: [2] }), twoParams)!.vectors!.map((v) => v.input), ["teamId", "status"]);
  // A single-input sink ignores a stray "vectors".
  assert.equal(parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), oneParam)!.vectors, undefined);
});

test("XSS: both inputs become vectors; severity still follows the XSS rule", () => {
  const f = parseXssJudgment(reply({ path: 1, vectors: [1, 2], severity: "critical" }), twoOutputs)!;
  assert.deepEqual(f.vectors!.map((v) => v.input), ["req.query.first", "req.query.last"]);
  assert.equal(f.severity, "high"); // reflected: the rule's level, whatever the reply says
  assert.deepEqual(withoutVectors(f), parseXssJudgment(reply({ path: 1, severity: "critical" }), twoOutputs));
});

test("access control: both identifiers become vectors; severity still follows the access rule", () => {
  const route = routeAt("/notes/:id/compare");
  const f = parseAccessJudgment(reply({ path: 1, vectors: [1, 2], severity: "high" }), route, ctx)!;
  assert.deepEqual(f.vectors!.map((v) => v.input), ["params.id", "query.otherId"]);
  assert.equal(f.severity, accessSeverity(ctx, route));
  assert.equal(f.severity, "critical");
  assert.deepEqual(withoutVectors(f), parseAccessJudgment(reply({ path: 1, severity: "high" }), route, ctx));
});

// ---- report --------------------------------------------------------------------------------------------------------

test("the CLI card lists every input and where it joins the sink, and says the fix must close all of them", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2], suggestedPatch: "async function list(teamId, status) {}" }), twoParams)!;
  const card = findingCard(makeColors(false), f, 1, 1, 100);
  assert.match(card, /Inputs \(2\) — one vulnerability, several inputs into the same sink; the fix must close every one\n {4}• teamId {2}routes\/notes\.js:7 → db\/notes\.js:5 {2}\(taint path above\)\n {4}• status {2}routes\/notes\.js:7 → db\/notes\.js:7\n/);
  assert.match(card, /Fix — suggested patch for db\/notes\.js; it must close all 2 inputs/);
  // Two inputs read in one statement have identical hop text; only the first is the one the taint path shows.
  const xss = findingCard(makeColors(false), parseXssJudgment(reply({ path: 2, vectors: [1, 2] }), twoOutputs)!, 1, 1, 100);
  assert.match(xss, /• req\.query\.last {3}routes\/pages\.js:7 {2}\(taint path above\)\n {4}• req\.query\.first {2}routes\/pages\.js:7\n/);
  const single = findingCard(makeColors(false), parseJudgment(sqliReply({ path: 1 }), oneParam)!, 1, 1, 100);
  assert.doesNotMatch(single, /Inputs|must close all/);
});

test("vectors are an additive JSON field", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), twoParams)!;
  const round = JSON.parse(JSON.stringify(f)) as Finding;
  assert.deepEqual(Object.keys(round).filter((k) => !(k in withoutVectors(f))), ["vectors"]);
  assert.deepEqual(round.vectors, f.vectors);
});

// ---- patch covers all ----------------------------------------------------------------------------------------------

/** Each input's state after applying `patch` to a copy of the fixture: "input open" or "input closed". */
function afterPatch(f: Finding, patch: string): string[] {
  const check = checkPatchVectors(root, { ...f, suggestedPatch: patch });
  assert.ok(check.applied, check.applied ? "" : check.reason);
  return check.vectors.map((v) => `${v.input} ${v.open ? "open" : "closed"}`);
}

test("SQLi: a patch binding both parameters closes both; binding one leaves the other open", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), twoParams)!;
  const both = `async function list(teamId, status) {
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = $1';
  const params = [teamId];
  if (status) {
    sql += ' AND status = $2';
    params.push(status);
  }
  const { rows } = await db.query(sql, params);
  return rows;
}`;
  const one = `async function list(teamId, status) {
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = $1';
  if (status) {
    sql += " AND status = '" + status + "'";
  }
  const { rows } = await db.query(sql, [teamId]);
  return rows;
}`;
  assert.deepEqual(afterPatch(f, both), ["teamId closed", "status closed"]);
  assert.deepEqual(afterPatch(f, one), ["teamId closed", "status open"]);
  // The fixture itself is untouched.
  assert.deepEqual(afterPatch(f, "async function list(teamId, status) { return []; }"), ["teamId closed", "status closed"]);
  assert.equal(groupBySink(traceProject(root).paths).find((g) => g.sink.line === 9)?.paths.length, 2);
});

test("SQLi: a placeholder numbered from the bound values' .length closes the input; text still concatenated stays open", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), twoParams)!;
  // The live fix for GET /api/appointments numbered its placeholder this way; Stage 1 still sees params (holding
  // teamId) flow into the SQL text through .length, which is a number, not the input.
  const both = `async function list(teamId, status) {
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = $1';
  const params = [teamId];
  if (status) {
    params.push(status);
    sql += ' AND status = $' + params.length;
  }
  const { rows } = await db.query(sql, params);
  return rows;
}`;
  const statusOpen = `async function list(teamId, status) {
  const params = [teamId];
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = $' + params.length;
  if (status) {
    sql += " AND status = '" + status + "'";
  }
  const { rows } = await db.query(sql, params);
  return rows;
}`;
  const teamIdOpen = `async function list(teamId, status) {
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = ' + teamId + ' AND length(title) > ' + teamId.length;
  const params = [];
  if (status) {
    params.push(status);
    sql += ' AND status = $1';
  }
  const { rows } = await db.query(sql, params);
  return rows;
}`;
  assert.deepEqual(afterPatch(f, both), ["teamId closed", "status closed"]);
  assert.deepEqual(afterPatch(f, statusOpen), ["teamId closed", "status open"]);
  assert.deepEqual(afterPatch(f, teamIdOpen), ["teamId open", "status closed"], "used as text too, not only as .length");
});

test("onlyLengthAt: a hop that uses the previous hop's variable only as .length cuts the path; any other use does not", () => {
  const fn = { file: "db/a.js", name: "f", startLine: 1, endLine: 9, code: "" };
  const hop = (line: number, code: string, kind: Hop["kind"] = "propagate"): Hop => ({ file: "db/a.js", line, code, kind, fn });
  const into = (code: string) => [hop(1, "async function f(id, status)  [param id]", "param"), hop(2, "const params = [id];"), hop(3, code, "build"), hop(4, "db.query(sql, params)", "sink")];
  assert.equal(onlyLengthAt(into("sql += ' AND status = $' + params.length")), true);
  assert.equal(onlyLengthAt(into("sql += ' AND status = $' + params?.length")), true);
  assert.equal(onlyLengthAt(into("sql += ' AND x = ' + params + ' -- ' + params.length")), false);
  assert.equal(onlyLengthAt(into("sql += ' AND x IN (' + params.join(',') + ')'")), false);
  assert.equal(onlyLengthAt(into("sql += ' AND x = ' + other.params.length")), false, "a property of another object is not the variable");
  // A source hop that destructures several names gives no single variable: never treated as cut.
  assert.equal(onlyLengthAt([hop(1, "const { a, b } = req.query;", "source"), hop(2, "sql += a.length", "build")]), false);
});

test("XSS: a patch encoding both inputs closes both; encoding one leaves the other open", () => {
  const f = parseXssJudgment(reply({ path: 1, vectors: [1, 2] }), twoOutputs)!;
  const helper = `function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
}
`;
  const handler = (last: string) => `${helper}router.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + escapeHtml(req.query.first) + ' ' + ${last} + '</h1>');
});`;
  assert.deepEqual(afterPatch(f, handler("escapeHtml(req.query.last)")), ["req.query.first closed", "req.query.last closed"]);
  assert.deepEqual(afterPatch(f, handler("req.query.last")), ["req.query.first closed", "req.query.last open"]);
});

test("access control: a patch checking both records closes both; checking one leaves the other open", () => {
  const f = parseAccessJudgment(reply({ path: 1, vectors: [1, 2] }), routeAt("/notes/:id/compare"), ctx)!;
  const both = `router.get('/:id/compare', async (req, res) => {
  const left = await notes.byId(req.params.id);
  const right = await notes.byId(req.query.otherId);
  if (!left || left.team_id !== req.user.teamId || !right || right.team_id !== req.user.teamId) return res.status(404).end();
  res.json({ left, right });
});`;
  const one = `router.get('/:id/compare', async (req, res) => {
  const left = await notes.byId(req.params.id);
  if (!left || left.team_id !== req.user.teamId) return res.status(404).end();
  const right = await notes.byId(req.query.otherId);
  res.json({ left, right });
});`;
  assert.deepEqual(afterPatch(f, both), ["params.id closed", "query.otherId closed"]);
  assert.deepEqual(afterPatch(f, one), ["params.id closed", "query.otherId open"]);
});

test("a patch that cannot be applied is reported, never counted as closing anything", () => {
  const f = parseJudgment(sqliReply({ path: 1, vectors: [1, 2] }), twoParams)!;
  const check = checkPatchVectors(root, { ...f, suggestedPatch: "// bind both parameters" });
  assert.equal(check.applied, false);
});
