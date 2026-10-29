// Offline tests for stored XSS (input written in one request, rendered in another) and browser DOM sinks — no API calls.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  buildXssPrompt,
  groupXssBySink,
  parseXssJudgment,
  sqlRead,
  sqlWrite,
  traceXssProject,
  xssReach,
  xssSeverity,
  type XssPath,
} from "../src/engine/xss/index.js";

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
      "api/views/workspace.js:1 markup drafts.text GET /workspace/drafts/:id/page written-by POST /workspace/drafts",
      "api/views/workspace.js:1 markup notices.message GET /workspace/notices/latest/page written-by POST /workspace/notices",
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
  assert.match(prompt, /say that the input is stored \(persisted\); state the viewer reach/);
  assert.match(prompt, /OTHER OUTPUTS OF THE SAME INPUT[^\n]*\n {2}- web\/src\/Excerpt\.jsx:4/);
  assert.match(prompt, /For this output the rule gives "critical"\./);
  assert.match(prompt, /\nHTTP ROUTE \(full path, including the prefix the router is mounted under\): GET \/forum\/posts\/:id\n/);
  assert.match(prompt, /the input enters at api\/routes\/posts\.js:7 and the output is at web\/src\/PostBody\.jsx:4/);

  const f = parseXssJudgment('[{"type":"XSS","cwe":"CWE-79","severity":"critical","path":1,"explanation":"e","suggestedPatch":"p"}]', group)!;
  assert.equal(f.type, "Cross-Site Scripting (Stored)");
  assert.equal(f.file, "api/routes/posts.js");
  assert.equal(f.sourceLine, 7);
  assert.equal(f.sinkFile, "web/src/PostBody.jsx");
  assert.equal(f.sinkLine, 4);
  assert.equal(f.httpRoute, "GET /forum/posts/:id");
  assert.equal(f.writeRoute, "POST /forum/posts", "the traced writer is carried to the verifier");
});

test("reflected groups keep the reflected type", () => {
  const reflected = traceXssProject(fileURLToPath(new URL("./xss-project", import.meta.url)));
  const [group] = groupXssBySink(reflected.xss);
  assert.equal(group.stored, undefined);
  assert.match(buildXssPrompt(group), /"type": "Cross-Site Scripting \(Reflected\)"/);
  assert.doesNotMatch(buildXssPrompt(group), /STORED flow/);
});

// ---- severity: an ordered rule on who receives the stored output, so it cannot drift between runs ----------------

const groups = groupXssBySink(trace.xss);
const groupAt = (file: string, stored: string) => groups.find((g) => g.sink.file === file && g.stored === stored)!;
const reply = (severity: string) => `[{"type":"XSS","cwe":"CWE-79","severity":"${severity}","path":1,"explanation":"e","suggestedPatch":"p"}]`;

test("viewer reach comes from the handler that renders or serves the stored value", () => {
  const reach = (file: string, stored: string) => {
    const r = xssReach(groupAt(file, stored));
    return `${r.level} ${r.reach?.route} ${r.reach?.at}`;
  };
  assert.equal(reach("api/views/post.js", "posts.body"), "public GET /forum/posts/:id/page api/routes/posts.js:15"); // reads no identity
  assert.equal(reach("web/src/PostBody.jsx", "posts.body"), "public GET /forum/posts/:id api/routes/posts.js:11"); // the JSON route serving it
  assert.equal(reach("api/views/workspace.js", "drafts.text"), "own-scope GET /workspace/drafts/:id/page api/routes/workspace.js:14"); // owner check
  assert.equal(reach("api/views/workspace.js", "notices.message"), "authenticated GET /workspace/notices/latest/page api/routes/workspace.js:24"); // signed in, unscoped
});

test("severity rule: stored reaching beyond the writer's scope is critical; own scope or reflected is high", () => {
  assert.equal(xssSeverity(groupAt("api/views/post.js", "posts.body")), "critical"); // public page
  assert.equal(xssSeverity(groupAt("web/src/PostBody.jsx", "posts.body")), "critical"); // public API → browser
  assert.equal(xssSeverity(groupAt("api/views/workspace.js", "notices.message")), "critical"); // any signed-in user
  assert.equal(xssSeverity(groupAt("api/views/workspace.js", "drafts.text")), "high"); // only the owning scope
  const reflected = groupXssBySink(traceXssProject(fileURLToPath(new URL("./xss-project", import.meta.url))).xss);
  assert.ok(reflected.length > 0 && reflected.every((g) => xssSeverity(g) === "high")); // a victim must open a crafted link
});

test("the prompt states the reach, the ordered rule, and the level it gives", () => {
  const prompt = buildXssPrompt(groupAt("api/views/workspace.js", "drafts.text"));
  assert.match(prompt, /VIEWER REACH[^\n]*: the owning scope only — GET \/workspace\/drafts\/:id\/page renders the stored value and restricts the record to the caller's identity \(api\/routes\/workspace\.js:14: draft\.owner_id !== req\.user\.id\)/);
  assert.match(prompt, /SEVERITY — XSS rule\. Check these IN ORDER and assign the FIRST one that matches/);
  assert.match(prompt, /For this output the rule gives "high"\./);
  assert.doesNotMatch(prompt, /SEVERITY — check these rules IN ORDER/); // the data-scope rule of the SQL/access judges is not used here
  assert.match(buildXssPrompt(groupAt("api/views/post.js", "posts.body")), /public — GET \/forum\/posts\/:id\/page renders the stored value, and its handler \(api\/routes\/posts\.js:15\) reads no authenticated identity/);
});

test("the finding's critical/high level is the rule's, whatever the model answered; a stated downgrade is kept", () => {
  const pub = groupAt("api/views/post.js", "posts.body");
  const own = groupAt("api/views/workspace.js", "drafts.text");
  assert.equal(parseXssJudgment(reply("high"), pub)!.severity, "critical");
  assert.equal(parseXssJudgment(reply("critical"), pub)!.severity, "critical");
  assert.equal(parseXssJudgment(reply("critical"), own)!.severity, "high");
  assert.equal(parseXssJudgment(reply("medium"), own)!.severity, "medium");
});
