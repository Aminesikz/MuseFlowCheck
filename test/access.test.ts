// Offline tests for access-control mode: Stage 1 evidence per route, and judge prompt/parse — no API calls.
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { assembleAccessContext, buildAccessPrompt, routeLabel, scopingEvidence, secureSiblings } from "../src/engine/access/index.js";
import { parseAccessJudgment } from "../src/engine/access/judge.js";
import { columnForValue, describeStatement, parseSchema } from "../src/engine/access/sql.js";
import { FindingParseError } from "../src/engine/parse.js";

const root = fileURLToPath(new URL("./access-project", import.meta.url));
const ctx = assembleAccessContext(root);
const route = (label: string) => ctx.routes.find((r) => routeLabel(r) === label)!;
const statuses = Object.fromEntries(ctx.routes.map((r) => [routeLabel(r), r.status]));

test("routes are composed from mounts and classified", () => {
  assert.deepEqual(statuses, {
    "GET /projects/:projectId": "candidate", // reads a team-owned row by id, no check
    "GET /projects/:projectId/owned": "guarded", // owner compared with identity in the service
    "GET /projects/:projectId/checked": "guarded", // owner compared with identity in the handler
    "GET /projects/:projectId/scoped": "guarded", // query constrained by the caller's team
    "DELETE /projects/:projectId": "candidate", // write, no check
    "PUT /projects/:projectId": "candidate", // the check runs only after the write
    "GET /share/:projectId": "public", // mounted without authentication
    "GET /tags/:tagId": "unscoped", // lookup table without an owner column
    "GET /teams/:teamId/totals": "guarded", // route middleware compares the path id with identity
    "GET /teams/:teamId/report": "candidate", // same data, no middleware
  });
});

test("identity comes from the middleware on the mount, with fields from what it assigns", () => {
  const r = route("GET /projects/:projectId");
  assert.equal(r.identity?.expression, "req.user");
  assert.equal(r.identity?.middleware?.name, "authenticate");
  assert.deepEqual(r.identity?.fields.sort(), ["id", "teamId"]);
});

test("accesses name the request field, the column it selects, and read vs write", () => {
  const show = (label: string) => route(label).accesses.map((a) => `${a.kind} ${a.location}.${a.field} → ${a.tables.join(",")}.${a.column}`);
  assert.deepEqual(show("GET /projects/:projectId"), ["read params.projectId → projects.id"]);
  assert.deepEqual(show("DELETE /projects/:projectId"), ["write params.projectId → projects.id"]);
  assert.deepEqual(show("PUT /projects/:projectId"), ["write params.projectId → projects.id"]); // body.title is not an identifier
  assert.deepEqual(show("GET /teams/:teamId/report"), ["read params.teamId → documents.team_id"]);
});

test("checks are recognized by kind and location", () => {
  const kinds = (label: string) => route(label).guards.map((g) => `${g.kind} @ ${g.file}:${g.line}`);
  assert.deepEqual(kinds("GET /projects/:projectId/owned"), ["resource owner compared with identity @ services/projects.js:10"]);
  assert.deepEqual(kinds("GET /projects/:projectId/checked"), ["resource owner compared with identity @ routes/projects.js:17"]);
  assert.deepEqual(kinds("GET /projects/:projectId/scoped"), ["query constrained by identity @ db/projects.js:6"]);
  assert.deepEqual(kinds("GET /teams/:teamId/totals"), ["request value compared with identity @ middleware/auth.js:14"]);
});

test("a check after a write does not cover it", () => {
  const r = route("PUT /projects/:projectId");
  assert.equal(r.guards.length, 1);
  assert.equal(r.status, "candidate");
});

test("scoping evidence cites the owner column, its schema line and foreign key", () => {
  const lines = scopingEvidence(ctx, route("GET /teams/:teamId/report"));
  assert.ok(lines.some((l) => l.startsWith("documents.team_id (db/migrations/001_init.sql:15, REFERENCES teams(id))")), lines.join("\n"));
  assert.ok(lines.some((l) => l.includes("params.teamId is used as documents.team_id")));
});

test("secure siblings rank same data / same path parameter first", () => {
  assert.deepEqual(secureSiblings(ctx, route("GET /teams/:teamId/report")).map(routeLabel)[0], "GET /teams/:teamId/totals");
  assert.equal(secureSiblings(ctx, route("DELETE /projects/:projectId")).length, 3);
});

test("the prompt carries the three signals and fixes type/CWE by access kind", () => {
  const write = buildAccessPrompt(ctx, route("DELETE /projects/:projectId"));
  assert.match(write, /A\. IDENTITY\n- authenticate \(middleware\/auth\.js:9\) sets req\.user = member/);
  assert.match(write, /B\. RESOURCE SCOPING/);
  assert.match(write, /Secure sibling routes \(they enforce a check\):\n- GET \/projects\/:projectId\/owned/);
  assert.match(write, /"type": "Broken Access Control",\n {2}"cwe": "CWE-862"/);
  assert.match(buildAccessPrompt(ctx, route("GET /projects/:projectId")), /"cwe": "CWE-639"/);
});

test("judgment: type/CWE come from the access kind; locations and taintPath from the trace", () => {
  const r = route("DELETE /projects/:projectId");
  const f = parseAccessJudgment('[{"type":"IDOR","cwe":"CWE-639","severity":"Critical","path":1,"explanation":"e","suggestedPatch":"p"}]', r)!;
  assert.equal(f.type, "Broken Access Control");
  assert.equal(f.cwe, "CWE-862");
  assert.equal(f.severity, "critical");
  assert.equal(f.file, "routes/projects.js");
  assert.equal(f.sourceLine, 26);
  assert.equal(f.sinkFile, "db/projects.js");
  assert.equal(f.sinkLine, 8);
  assert.equal(f.confidence, "suspected");
  assert.equal(f.httpRoute, "DELETE /projects/:projectId"); // route carried to the verifier for :id discovery
  assert.ok(f.taintPath.length >= 4);
  assert.equal(parseAccessJudgment("[]", r), null);
  assert.throws(() => parseAccessJudgment('[{"severity":"urgent"}]', r), FindingParseError);
});

// ---- prompt hygiene -----------------------------------------------------------------------------

/** Distinctive identifiers from every test project and fixture (paths, route strings, longer local names). */
function identifiers(dir: string): string[] {
  const ids = new Set<string>();
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      const abs = path.join(d, name);
      if (statSync(abs).isDirectory()) walk(abs);
      else if (/\.(js|ts|sql)$/.test(name)) {
        const base = name.replace(/\.\w+$/, "");
        if (base.length >= 6) ids.add(base); // short names ("user", "index") are ordinary words
        const code = readFileSync(abs, "utf8");
        for (const m of code.matchAll(/['"`](\/[\w/:-]+)['"`]/g)) ids.add(m[1]);
        for (const m of code.matchAll(/(?:const|let|function|TABLE)\s+(\w{6,})/g)) ids.add(m[1]);
      }
    }
  };
  walk(fileURLToPath(new URL(dir, import.meta.url)));
  return [...ids];
}

test("the prompt's fixed instructions name nothing from the test projects or fixtures", () => {
  const prompt = buildAccessPrompt(ctx, route("GET /projects/:projectId"));
  const fixed = prompt.split("ROUTE:")[0] + prompt.slice(prompt.indexOf("SEVERITY —"));
  for (const dir of ["./access-project", "./project-scan", "./crossfile-styles", "../fixtures", "../test-cases"]) {
    // Generic programming words the instructions legitimately use.
    const generic = ["express", "client", "handler", "router", "request", "response", "middleware", "statement", "fields"];
    for (const id of identifiers(dir).filter((x) => !generic.includes(x))) {
      assert.ok(!new RegExp(`\\b${id.replace(/[/:]/g, "\\$&")}\\b`).test(fixed), `prompt mentions "${id}" from ${dir}`);
    }
  }
});

// ---- SQL helpers --------------------------------------------------------------------------------

test("schema parsing: inline and table-level foreign keys", () => {
  const [t] = parseSchema("CREATE TABLE IF NOT EXISTS notes (\n  id SERIAL PRIMARY KEY,\n  org_id INT REFERENCES orgs(id),\n  author INT,\n  FOREIGN KEY (author) REFERENCES users\n);", "s.sql");
  assert.equal(t.name, "notes");
  assert.deepEqual(t.columns.map((c) => [c.name, c.line, c.references?.table]), [["id", 2, undefined], ["org_id", 3, "orgs"], ["author", 4, "users"]]);
});

test("statements: verb, tables, and the column a value selects", () => {
  assert.deepEqual(describeStatement("UPDATE notes SET body = $1 WHERE id = $2"), { verb: "update", tables: ["notes"] });
  assert.equal(columnForValue("UPDATE notes SET body = $1 WHERE id = $2", { placeholder: 2 }), "id");
  assert.equal(columnForValue("SELECT * FROM notes WHERE org_id = ? AND id = ?", { placeholder: 2 }), "id");
  assert.equal(columnForValue("SELECT * FROM notes WHERE org_id = {{orgId}}", { name: "orgId" }), "org_id");
  assert.equal(columnForValue("INSERT INTO notes (org_id, body) VALUES ($1, $2)", { placeholder: 1 }), "org_id");
});
