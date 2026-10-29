// Offline tests for stored XSS (input written in one request, rendered in another) and browser DOM sinks — no API calls.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { buildXssPrompt, groupXssBySink, parseXssJudgment, sqlRead, sqlWrite, traceXssProject, type XssPath } from "../src/engine/xss/index.js";

const root = fileURLToPath(new URL("./xss-stored-project", import.meta.url));
const trace = traceXssProject(root);
const at = (p: XssPath) => `${p.hops.at(-1)!.file}:${p.hops.at(-1)!.line}`;
const kinds = (p: XssPath) => p.hops.map((h) => `${h.kind} ${h.file}:${h.line}`);

test("SQL writes: the parameter index per column", () => {
  assert.deepEqual(sqlWrite("UPDATE notes SET text = $1, pinned = $2 WHERE id = $3"), { table: "notes", columns: new Map([["text", 0], ["pinned", 1]]) });
  assert.deepEqual(sqlWrite('INSERT INTO "public"."notes" (owner, text) VALUES (?, ?)'), { table: "notes", columns: new Map([["owner", 0], ["text", 1]]) });
  assert.deepEqual(sqlWrite("UPDATE notes SET seen = now(), text = ? WHERE id = ?")?.columns, new Map([["text", 0]]));
  assert.equal(sqlWrite("SELECT 1"), undefined);
});

test("SQL reads: the table and the property names the rows carry", () => {
  assert.deepEqual(sqlRead("SELECT n.id, n.text AS body FROM notes n WHERE id = $1"), { table: "notes", columns: ["id", "body"] });
  assert.deepEqual(sqlRead("SELECT * FROM notes"), { table: "notes", columns: ["*"] });
  assert.deepEqual(sqlRead("UPDATE notes SET text = $1 WHERE id = $2 RETURNING id, text"), { table: "notes", columns: ["id", "text"] });
  assert.equal(sqlRead("DELETE FROM notes WHERE id = $1"), undefined);
});

test("stored input reaching output raw is a candidate, on the server and in the browser", () => {
  const raw = trace.xss.filter((p) => !p.encoded);
  assert.deepEqual(
    raw.map((p) => `${at(p)} ${p.context} ${p.stored} ${p.route} written-by ${p.writtenBy}`),
    [
      "api/views/post.js:7 markup posts.body GET /forum/posts/:id/page written-by POST /forum/posts",
      "web/src/PostBody.jsx:4 dom-html posts.body GET /forum/posts/:id written-by POST /forum/posts",
    ],
  );
});

test("encoded or escaped renders of stored input are listed, not candidates", () => {
  const encoded = trace.xss.filter((p) => p.encoded);
  assert.deepEqual(
    encoded.map((p) => `${at(p)} ${p.context} ${p.encoder}`),
    [
      "api/views/post.js:5 markup escape (package 'escape-html')",
      "web/src/Excerpt.jsx:4 jsx-text rendered as a JSX text child (React escapes it)", // same stored body as PostBody
      "web/src/PostTitle.jsx:5 dom-html DOMPurify.sanitize (package 'dompurify')",
    ],
  );
});

test("only columns written from request input are stored taint: a column the app never writes from input is not", () => {
  const sinks = trace.xss.map(at);
  assert.ok(!sinks.includes("api/views/post.js:6"), "post.author is not written from request input");
  assert.ok(!sinks.includes("web/src/Feed.jsx:20"), "nor in the browser");
});

test("the stored path shows the write request, then the read back and the rendering request", () => {
  const p = trace.xss.find((c) => at(c) === "api/views/post.js:7")!;
  assert.deepEqual(kinds(p), [
    "source api/routes/posts.js:7",
    "call api/routes/posts.js:7",
    "param api/services/posts.js:4",
    "call api/services/posts.js:5",
    "param api/db/posts.js:7",
    "store api/db/posts.js:8",
    "entry api/routes/posts.js:15", // the rendering request starts here
    "call api/routes/posts.js:16",
    "param api/services/posts.js:12",
    "load api/db/posts.js:13", // read with no request-tainted argument: Number(id)
    "call api/services/posts.js:13",
    "param api/db/posts.js:12",
    "propagate api/services/posts.js:13",
    "call api/services/posts.js:14",
    "param api/views/post.js:3",
    "sink api/views/post.js:7",
  ]);
  assert.match(p.hops[5].code, /\[stores posts\.body\]$/);
  assert.match(p.hops[9].code, /\[reads posts\.body\]$/);
});

test("browser path: JSON response → fetch → state set in a promise callback → component props → dangerouslySetInnerHTML", () => {
  const p = trace.xss.find((c) => at(c) === "web/src/PostBody.jsx:4")!;
  const browser = kinds(p).slice(kinds(p).findIndex((k) => k.startsWith("load web/")));
  assert.deepEqual(browser, [
    "load web/src/client.js:2",
    "call web/src/Feed.jsx:11",
    "param web/src/client.js:1",
    "call web/src/Feed.jsx:11",
    "param web/src/Feed.jsx:11",
    "propagate web/src/Feed.jsx:11",
    "call web/src/Feed.jsx:18",
    "param web/src/PostBody.jsx:3",
    "sink web/src/PostBody.jsx:4",
  ]);
  assert.match(p.hops.find((h) => h.kind === "propagate" && h.file === "api/routes/posts.js")!.code, /\[sent as JSON by GET \/forum\/posts\/:id\]$/);
  assert.match(p.hops.find((h) => h.file === "web/src/Feed.jsx" && h.kind === "propagate")!.code, /\[state post\]$/);
});

test("stored groups: type, two-request framing, output kind, and escaped renders of the same value for contrast", () => {
  const group = groupXssBySink(trace.xss).find((g) => g.sink.file === "web/src/PostBody.jsx")!;
  assert.equal(group.stored, "posts.body");
  const prompt = buildXssPrompt(group);
  assert.match(prompt, /This is a STORED flow across two requests: request input is written to the database column posts\.body by POST \/forum\/posts/);
  assert.match(prompt, /here: inserted into the page as HTML in the browser \(React dangerouslySetInnerHTML/);
  assert.match(prompt, /"type": "Cross-Site Scripting \(Stored\)"/);
  assert.match(prompt, /say that the input is stored \(persisted\) and who it reaches/);
  assert.match(prompt, /OTHER OUTPUTS OF THE SAME INPUT[^\n]*\n {2}- web\/src\/Excerpt\.jsx:4/);
  assert.match(prompt, /A stored XSS needs no crafted link/);

  const f = parseXssJudgment('[{"type":"XSS","cwe":"CWE-79","severity":"critical","path":1,"explanation":"e","suggestedPatch":"p"}]', group)!;
  assert.equal(f.type, "Cross-Site Scripting (Stored)");
  assert.equal(f.file, "api/routes/posts.js");
  assert.equal(f.sourceLine, 7);
  assert.equal(f.sinkFile, "web/src/PostBody.jsx");
  assert.equal(f.sinkLine, 4);
  assert.equal(f.httpRoute, "GET /forum/posts/:id");
});

test("reflected groups keep the reflected type", () => {
  const reflected = traceXssProject(fileURLToPath(new URL("./xss-project", import.meta.url)));
  const [group] = groupXssBySink(reflected.xss);
  assert.equal(group.stored, undefined);
  assert.match(buildXssPrompt(group), /"type": "Cross-Site Scripting \(Reflected\)"/);
  assert.doesNotMatch(buildXssPrompt(group), /STORED flow/);
});
