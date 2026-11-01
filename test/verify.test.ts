// Offline tests for the verification stage: local-only guard, request/auth, the deterministic oracle, PoC parsing,
// end-to-end verifyFinding against a loopback mock server, and patch-proof orchestration. No model or real app.
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import {
  assertLocalTarget,
  buildPocPrompt,
  emptyResult,
  evaluate,
  findOwnerField,
  fillParam,
  parsePoc,
  routeParam,
  sameResponse,
  Target,
  TargetError,
  sqlSinkKind,
  verifyFinding,
  verifyPatch,
} from "../src/engine/verify/index.js";
import { FindingParseError } from "../src/engine/parse.js";
import type { Finding } from "../src/types/index.js";

// ---- local-only guard ---------------------------------------------------------------------------

test("assertLocalTarget accepts only loopback hosts", () => {
  for (const url of ["http://localhost:4000", "http://127.0.0.1:3000/base", "https://app.localhost", "http://x.test:80", "http://[::1]:5000"]) {
    assert.doesNotThrow(() => assertLocalTarget(url), url);
  }
  for (const url of ["http://example.com", "http://169.254.169.254", "http://localhost.evil.com", "http://127.0.0.1.evil.com", "https://10.0.0.1", "ftp://localhost", "not-a-url"]) {
    assert.throws(() => assertLocalTarget(url), TargetError, url);
  }
});

test("Target construction refuses a non-local host", () => {
  assert.throws(() => new Target({ url: "http://attacker.example" }), TargetError);
});

// ---- deterministic oracle -----------------------------------------------------------------------

test("evaluate: marker only when present in the exploit and absent from the baseline", () => {
  assert.equal(evaluate({ type: "marker", value: "ZZMARK" }, { status: 200, body: "[]" }, { status: 200, body: '[{"x":"ZZMARK"}]' }).success, true);
  assert.equal(evaluate({ type: "marker", value: "ZZMARK" }, { status: 200, body: "ZZMARK" }, { status: 200, body: "ZZMARK" }).success, false);
});

test("evaluate: a marker the target only echoes back never confirms — a missing route, or a page repeating the input", () => {
  // Express's 404 page repeats the path, so the injected marker came back in the exploit's 404 (a live false confirmation).
  const page = (path: string) => `<!DOCTYPE html><html lang="en"><head><title>Error</title></head><body><pre>Cannot GET ${path}</pre></body></html>`;
  const path = "/invoices/0%20UNION%20SELECT%209999,%200,%20&#39;INJECTED1337&#39;".replace(/&#39;/g, "'");
  const missing = evaluate({ type: "marker", value: "INJECTED1337" }, { status: 404, body: page("/invoices/1"), path: "/invoices/1" }, { status: 404, body: page(path.replace(/'/g, "&#39;")), path });
  assert.equal(missing.success, false);
  assert.match(missing.detail, /baseline request returned status 404, so the route did not answer normally on this target/);

  // A search page that answers 200 and repeats q (URL-encoded, HTML-escaped) but returns no injected row.
  const q = "' UNION SELECT NULL,'PWN_MARK_42',NULL --";
  const url = `/search?q=${encodeURIComponent(q).replace(/%20/g, "+")}`;
  const echoPage = `<h1>Results for &#39; UNION SELECT NULL,&#39;PWN_MARK_42&#39;,NULL --</h1><p>No results</p>`;
  const echo = evaluate({ type: "marker", value: "PWN_MARK_42" }, { status: 200, body: "<h1>Results for shoes</h1><ul><li>Shoe</li></ul>", path: "/search?q=shoes" }, { status: 200, body: echoPage, path: url });
  assert.equal(echo.success, false);
  assert.match(echo.detail, /appeared in the exploit response only as an echo of the request \(status 200\), not as data the query returned/);

  // The same page also listing the row the injected SELECT returned: that occurrence is data, so it confirms.
  const returned = evaluate(
    { type: "marker", value: "PWN_MARK_42" },
    { status: 200, body: "<h1>Results for shoes</h1><ul><li>Shoe</li></ul>", path: "/search?q=shoes" },
    { status: 200, body: `${echoPage.replace("<p>No results</p>", "")}<ul><li>Shoe</li><li>PWN_MARK_42</li></ul>`, path: url },
  );
  assert.equal(returned.success, true);
  assert.equal(returned.detail, 'injected marker "PWN_MARK_42" appeared in the exploit response and not in the baseline');

  // An echo of a JSON body (an error message repeating the input) does not confirm either.
  const sent = JSON.stringify({ name: "x' UNION SELECT 'BODY_MARK_7' --" });
  const bodyEcho = evaluate({ type: "marker", value: "BODY_MARK_7" }, { status: 200, body: '{"ok":true}', path: "/api/items" }, { status: 400, body: `{"error":"invalid name: x' UNION SELECT 'BODY_MARK_7' --"}`, path: "/api/items", sent });
  assert.equal(bodyEcho.success, false);

  // A UNION row in a JSON API response confirms, as before.
  const api = evaluate(
    { type: "marker", value: "SQLI_MARKER_ABC" },
    { status: 200, body: '{"barbers":[{"id":1,"name":"Marcus"}]}', path: "/api/barbers/search?q=mar" },
    { status: 200, body: '{"barbers":[{"id":null,"shop_id":null,"name":"SQLI_MARKER_ABC","specialty":null}]}', path: "/api/barbers/search?q=%27+UNION+SELECT+NULL%2CNULL%2C%27SQLI_MARKER_ABC%27%2CNULL--+" },
  );
  assert.equal(api.success, true);
});

test("evaluate: more-rows compares array lengths, with an optional field", () => {
  assert.equal(evaluate({ type: "more-rows" }, { status: 200, body: "[1,2]" }, { status: 200, body: "[1,2,3,4]" }).success, true);
  assert.equal(evaluate({ type: "more-rows", field: "rows" }, { status: 200, body: '{"rows":[1]}' }, { status: 200, body: '{"rows":[1,2]}' }).success, true);
  assert.equal(evaluate({ type: "more-rows" }, { status: 200, body: "[1,2]" }, { status: 200, body: "[1,2]" }).success, false);
});

test("evaluate: field-differs needs a 2xx exploit and a different owner value", () => {
  const b = { status: 200, body: '{"revenue":{"shopId":1}}' };
  assert.equal(evaluate({ type: "field-differs", field: "shopId" }, b, { status: 200, body: '{"revenue":{"shopId":2}}' }).success, true);
  assert.equal(evaluate({ type: "field-differs", field: "shopId" }, b, { status: 200, body: '{"revenue":{"shopId":1}}' }).success, false);
  assert.equal(evaluate({ type: "field-differs", field: "shopId" }, b, { status: 403, body: '{"revenue":{"shopId":2}}' }).success, false);
});

test("evaluate: status-unblocked needs a rejected baseline and a 2xx exploit with a body", () => {
  assert.equal(evaluate({ type: "status-unblocked" }, { status: 403, body: "no" }, { status: 200, body: "{}" }).success, true);
  assert.equal(evaluate({ type: "status-unblocked" }, { status: 200, body: "ok" }, { status: 200, body: "{}" }).success, false);
  assert.equal(evaluate({ type: "status-unblocked" }, { status: 403, body: "no" }, { status: 200, body: "" }).success, false);
});

// ---- PoC parsing --------------------------------------------------------------------------------

test("parsePoc parses requests and a check; rejects malformed output", () => {
  const poc = parsePoc('```json\n[{"baseline":{"method":"get","path":"/api/x"},"exploit":{"method":"GET","path":"/api/x","query":{"q":"1 OR 1=1"}},"check":{"type":"more-rows"},"rationale":"r"}]\n```');
  assert.equal(poc.baseline.method, "GET");
  assert.deepEqual(poc.exploit.query, { q: "1 OR 1=1" });
  assert.equal(poc.check.type, "more-rows");
  assert.throws(() => parsePoc("[]"), FindingParseError);
  assert.throws(() => parsePoc('[{"baseline":{"method":"GET","path":"x"},"exploit":{"method":"GET","path":"/y"},"check":{"type":"more-rows"}}]'), FindingParseError); // path not absolute
  assert.throws(() => parsePoc('[{"baseline":{"method":"GET","path":"/x"},"exploit":{"method":"GET","path":"/y"},"check":{"type":"nope"}}]'), FindingParseError);
});

// ---- loopback mock app + end-to-end verifyFinding -----------------------------------------------

let server: Server;
let base: string;

// A tiny in-memory appointments store for the ":id" IDOR tests. The :id route has NO ownership check (the vulnerable
// behavior): any authenticated caller can read/modify any id. apptLog records the :id requests so a test can assert
// whether probing happened. shop 1 owns ids 1–2, shop 2 owns ids 3–4.
type Appt = { id: number; shop_id: number; status: string; customer_name?: string };
let appts: Record<number, Appt> = {};
const apptLog: string[] = [];
const postLog: string[] = []; // titles the write route inserted, to show a SQLi proof really mutated the target
function resetAppts(): void {
  appts = {
    1: { id: 1, shop_id: 1, status: "booked" },
    2: { id: 2, shop_id: 1, status: "completed" },
    3: { id: 3, shop_id: 2, status: "booked" },
    4: { id: 4, shop_id: 2, status: "completed" },
  };
  apptLog.length = 0;
}

before(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const method = (req.method ?? "GET").toUpperCase();
      const authed = (req.headers.authorization ?? "") === "Bearer tenant-1";
      const raw = Buffer.concat(chunks).toString();
      let body: Record<string, unknown> = {};
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        body = {};
      }
      const json = (status: number, b: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(b));
      };
      if (url.pathname === "/api/auth/login") return json(200, { token: "tenant-1" });
      if (!authed) return json(401, { error: "unauthorized" });

      const byId = /^\/api\/appointments\/(\d+)$/.exec(url.pathname); // :id route — no ownership check
      if (byId) {
        const id = Number(byId[1]);
        apptLog.push(`${method} ${url.pathname}`);
        const row = appts[id];
        if (!row) return json(404, { error: "not found" });
        if (method === "PATCH") {
          if (typeof body.status === "string") row.status = body.status; // only status is writable (like the fixture)
          return json(200, row);
        }
        if (method === "DELETE") return (delete appts[id], json(200, { deleted: id }));
        return json(200, row);
      }
      if (url.pathname === "/api/appointments") {
        const status = url.searchParams.get("status") ?? "";
        const injected = /'|union|or\s+1=1/i.test(status); // the "vulnerable" query dumps all shops
        return json(200, { appointments: injected ? [{ shop_id: 1 }, { shop_id: 1 }, { shop_id: 2 }, { shop_id: 2 }] : [{ shop_id: 1 }, { shop_id: 1 }] });
      }
      // A write route whose INSERT concatenates input (like sc_pro's register/write): every POST inserts a row,
      // whatever the request. It records what it stored so a test can see the mutation really happened.
      if (url.pathname === "/api/posts" && method === "POST") {
        const title = String(body.title ?? "");
        postLog.push(title);
        // Returns the stored titles as server-generated markup (each behind a "row<i>:" prefix), so a marker that
        // was stored comes back as the server's own data, not as a bare echo of the request body.
        const listing = postLog.map((t, i) => `row${i}:${t}`).join("|");
        return json(200, { ok: true, listing });
      }
      const revenue = /^\/api\/shops\/(\d+)\/revenue$/.exec(url.pathname); // IDOR: returns whatever shop is asked for
      if (revenue) return json(200, { revenue: { shopId: Number(revenue[1]), totalCents: 1000 * Number(revenue[1]) } });
      return json(404, { error: "not found" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => server.close());

const sqliFinding: Finding = {
  type: "SQL Injection", cwe: "CWE-89", severity: "critical", file: "routes/appointments.js", sourceLine: 11,
  sinkFile: "db/appointments.js", sinkLine: 14, taintPath: ["routes/appointments.js:11 req.query.status", "db/appointments.js:14 pool.query(sql)"],
  explanation: "status is concatenated into SQL", suggestedPatch: "function findByShop(){}", confidence: "suspected",
};
const idorFinding: Finding = {
  type: "IDOR", cwe: "CWE-639", severity: "high", file: "routes/shops.js", sourceLine: 7, sinkFile: "db/shops.js", sinkLine: 12,
  taintPath: ["routes/shops.js:9 req.params.shopId", "db/shops.js:12 pool.query(sql)"], explanation: "no shop check", suggestedPatch: "x", confidence: "suspected",
};

const completeWith = (poc: object) => async () => JSON.stringify([poc]);

test("the PoC prompt pins the real HTTP route when the finding carries one, and does not when it doesn't", () => {
  const withRoute = buildPocPrompt({ ...sqliFinding, httpRoute: "GET /api/barbers/search" });
  assert.match(withRoute, /GET \/api\/barbers\/search/);
  assert.match(withRoute, /use that exact method and path/);
  assert.doesNotMatch(buildPocPrompt(sqliFinding), /use that exact method and path/);
});

test("the PoC prompt asks for a baseline that returns the caller's own data, not a no-match request", () => {
  const prompt = buildPocPrompt(sqliFinding);
  assert.match(prompt, /baseline must return some of the caller's own data/);
  assert.match(prompt, /re-runs the same baseline after a fix is applied/);
  assert.doesNotMatch(prompt, /few or zero rows/);
});

test("verifyFinding confirms a SQLi finding when the exploit returns more rows than the baseline", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const poc = {
    baseline: { method: "GET", path: "/api/appointments", query: { status: "booked" } },
    exploit: { method: "GET", path: "/api/appointments", query: { status: "' OR '1'='1" } },
    check: { type: "more-rows", field: "appointments" },
    rationale: "injecting a true condition drops the shop filter",
  };
  const f = await verifyFinding(sqliFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.verification?.outcome, "confirmed");
  assert.match(f.verification!.summary, /2 row\(s\); exploit returned 4/);
  assert.equal(f.verification?.exploit?.status, 200);
});

test("verifyFinding confirms an IDOR finding via a cross-tenant field difference", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const poc = {
    baseline: { method: "GET", path: "/api/shops/1/revenue" },
    exploit: { method: "GET", path: "/api/shops/2/revenue" },
    check: { type: "field-differs", field: "shopId" },
    rationale: "requesting another shop's id returns its revenue",
  };
  const f = await verifyFinding(idorFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /shopId=2.*vs the baseline's 1/);
});

test("verifyFinding marks a finding unverified when the exploit matches the baseline", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const poc = {
    baseline: { method: "GET", path: "/api/appointments", query: { status: "booked" } },
    exploit: { method: "GET", path: "/api/appointments", query: { status: "completed" } }, // not an injection
    check: { type: "more-rows", field: "appointments" },
    rationale: "benign",
  };
  const f = await verifyFinding(sqliFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /execution did not confirm/);
});

test("verifyFinding marks a finding unverified when the model's PoC is unusable", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const f = await verifyFinding(sqliFinding, target, { complete: async () => "not json at all" });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /could not generate a usable PoC/);
});

// ---- mutating SQLi proofs must never mutate silently (snapshot-and-restore discipline) ----------

// A SQLi finding whose sink is a write: the traced path's build hop names the INSERT, so the verifier knows a proof
// against it writes. The INSERT has no clean handle to revert (new rows), so the proof must flag RE-SEED, not restore.
const sqliWriteFinding: Finding = {
  type: "SQL Injection", cwe: "CWE-89", severity: "critical", file: "routes/post.js", sourceLine: 30, sinkFile: "routes/post.js", sinkLine: 36,
  httpRoute: "POST /api/posts",
  taintPath: [
    "routes/post.js:30  const { title, content } = req.body;",
    "routes/post.js:34  const sql = `INSERT INTO posts (title, content) VALUES ('${title}', '${content}')`;",
    "routes/post.js:36  db.query(sql, (err) => {})",
  ],
  explanation: "title is concatenated into an INSERT", suggestedPatch: "x", confidence: "suspected",
};

test("sqlSinkKind reads the statement verb off the traced path: INSERT/UPDATE/DELETE write, SELECT reads", () => {
  assert.equal(sqlSinkKind(sqliWriteFinding), "write");
  assert.equal(sqlSinkKind({ ...sqliWriteFinding, taintPath: ["r.js:1 const sql = `UPDATE posts SET x=1`", "r.js:2 db.query(sql)"] }), "write");
  assert.equal(sqlSinkKind({ ...sqliWriteFinding, taintPath: ["r.js:1 const sql = `SELECT * FROM posts WHERE id = ${id}`", "r.js:2 db.query(sql)"] }), "read");
  assert.equal(sqlSinkKind({ ...sqliWriteFinding, taintPath: ["r.js:1 db.query(sql)"] }), undefined); // no verb visible
});

test("a mutating SQLi proof that CONFIRMS still flags RE-SEED and names the inserted marker", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const poc = {
    baseline: { method: "POST", path: "/api/posts", body: { title: "hello" } },
    exploit: { method: "POST", path: "/api/posts", body: { title: "ZZMARK42" } }, // a stored sentinel, returned behind the server's "row<i>:" prefix (not a bare echo)
    check: { type: "marker", value: "ZZMARK42" },
    rationale: "the injected INSERT stores a sentinel row that the listing then returns",
  };
  postLog.length = 0;
  const f = await verifyFinding(sqliWriteFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /Confirmed:/);
  assert.match(f.verification!.summary, /RE-SEED RECOMMENDED/);
  assert.match(f.verification!.summary, /ZZMARK42/); // names what it may have left
  assert.ok(postLog.length > 0, "the proof really did write to the target");
});

test("a mutating SQLi proof that does NOT confirm is still not silent — RE-SEED is reported (the sc_pro register case)", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const poc = {
    baseline: { method: "POST", path: "/api/posts", body: { title: "benign_user" } },
    exploit: { method: "POST", path: "/api/posts", body: { title: "evil" } }, // inserts, but no marker echoed back → unverified
    check: { type: "marker", value: "NEVER_APPEARS_99" },
    rationale: "the injected INSERT adds a row",
  };
  postLog.length = 0;
  const f = await verifyFinding(sqliWriteFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /execution did not confirm/);
  assert.match(f.verification!.summary, /RE-SEED RECOMMENDED/);
  assert.equal(postLog.length, 2, "both benign and exploit requests inserted rows");
});

test("a read-only SQLi proof (SELECT) is not falsely flagged for re-seeding", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  const readFinding: Finding = {
    ...sqliFinding,
    taintPath: ["routes/appointments.js:11  const sql = `SELECT * FROM appointments WHERE status = '${status}'`;", "db/appointments.js:14 pool.query(sql)"],
  };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments", query: { status: "booked" } },
    exploit: { method: "GET", path: "/api/appointments", query: { status: "' OR '1'='1" } },
    check: { type: "more-rows", field: "appointments" },
    rationale: "a true condition drops the filter",
  };
  const f = await verifyFinding(readFinding, target, { complete: completeWith(poc) });
  assert.equal(f.confidence, "confirmed");
  assert.doesNotMatch(f.verification!.summary, /RE-SEED/);
});

test("Target exchanges login credentials for a token once", async () => {
  let logins = 0;
  const fetchCounting: typeof fetch = (url, init) => {
    if (String(url).endsWith("/api/auth/login")) logins++;
    return fetch(url, init);
  };
  const target = new Target({ url: base, auth: { kind: "login", path: "/api/auth/login", body: { email: "a@b.test" }, tokenField: "token" }, fetch: fetchCounting });
  const first = await target.request("GET", "/api/appointments", { query: { status: "x" } });
  const second = await target.request("GET", "/api/appointments", { query: { status: "y" } });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(logins, 1); // token cached after the first exchange
});

test("a GET request never carries a body; an object body folds into the query string", async () => {
  const target = new Target({ url: base, auth: { kind: "token", token: "tenant-1" } });
  // The model sometimes emits a GET PoC with a body; fetch would throw. It must be folded into the query instead.
  const res = await target.request("GET", "/api/appointments", { body: { status: "' OR '1'='1" } });
  assert.equal(res.status, 200);
  assert.match(res.path, /status=/);
  assert.equal(JSON.parse(res.body).appointments.length, 4); // the injected status still reached the query
});

// ---- IDOR cross-scope id discovery --------------------------------------------------------------

test("routeParam and fillParam parse and fill the last :param segment", () => {
  assert.deepEqual(routeParam("GET /api/appointments/:id"), { method: "GET", template: "/api/appointments/:id", param: "id" });
  assert.equal(fillParam(routeParam("GET /api/appointments/:id")!, 7), "/api/appointments/7");
  assert.equal(routeParam("GET /api/appointments"), undefined); // no path parameter
  const nested = routeParam("PATCH /api/shops/:shopId/appointments/:id")!;
  assert.equal(nested.param, "id");
  assert.equal(fillParam(nested, 9), "/api/shops/:shopId/appointments/9"); // only the last parameter is filled
});

const idorToken = { kind: "token" as const, token: "tenant-1" };
const idorFieldCheck = { type: "field-differs" as const, field: "shop_id" };

test("IDOR read: discovers a cross-scope id when the model's guessed victim is same-scope", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id" };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" }, // own, shop 1
    exploit: { method: "GET", path: "/api/appointments/2" }, // model guessed id 2 — also shop 1, so the first try fails
    check: idorFieldCheck,
    rationale: "requesting another shop's appointment returns it",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /found id 3 owned by shop_id=2/);
  assert.equal(f.verification!.exploit?.path, "/api/appointments/3");
});

test("IDOR read: a correct guess confirms on the first try without probing", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id" };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" }, // shop 1
    exploit: { method: "GET", path: "/api/appointments/3" }, // shop 2 — the guess is already cross-scope
    check: idorFieldCheck,
    rationale: "requesting another shop's appointment returns it",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed");
  assert.doesNotMatch(f.verification!.summary, /Probed/); // confirmed on the model's own exploit
  assert.deepEqual(apptLog, ["GET /api/appointments/1", "GET /api/appointments/3"]); // no probe requests
});

test("IDOR read: no cross-scope id within the probe range leaves the finding unverified", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id" };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" },
    exploit: { method: "GET", path: "/api/appointments/2" }, // same-scope guess; range 2 cannot reach shop 2's ids 3–4
    check: idorFieldCheck,
    rationale: "r",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 2 } });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /no resource owned by another scope was found probing GET \/api\/appointments\/:id for ids 1\.\.2/);
});

test("IDOR write: discovers a foreign id, proves the cross-scope write, restores it, and leaves own data intact", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1", body: { status: "completed" } }, // own
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { status: "cancelled" } }, // guessed id 2 — own
    check: idorFieldCheck,
    rationale: "patching another shop's appointment succeeds",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /found id 3 owned by shop_id=2/);
  assert.match(f.verification!.summary, /status changed from "booked" to "cancelled"/);
  assert.match(f.verification!.summary, /Fixture state: restored/);
  assert.equal(appts[3].status, "booked"); // the foreign resource was reverted
  assert.equal(appts[2].status, "completed"); // the model's guessed exploit was never sent
  assert.equal(appts[1].status, "booked"); // own resource left as-is (the own "baseline" was a no-op write)
});

test("IDOR write: when the model's value equals the target's current value, a differing own value is used", async () => {
  resetAppts();
  appts[3].status = "cancelled"; // the foreign resource already has the status the model will try to set
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1", body: { status: "booked" } },
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { status: "cancelled" } }, // same as id 3's current value → a no-op
    check: idorFieldCheck,
    rationale: "patching another shop's appointment succeeds",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed"); // the proof substituted the caller's own "booked" so the write is observable
  assert.match(f.verification!.summary, /status changed from "cancelled" to "booked"/);
  assert.equal(appts[3].status, "cancelled"); // reverted to what it was before the proof
});

test("IDOR write: when the model sends no body, it harvests a changing value from a probed resource", async () => {
  resetAppts();
  // The baseline/own resource shares the foreign's status, so a differing value can only come from ANOTHER probed row.
  appts[1] = { id: 1, shop_id: 1, status: "cancelled" }; // own (the baseline path) — same status as the foreign
  appts[2] = { id: 2, shop_id: 1, status: "completed" }; // own, probed — supplies the "completed" the proof uses
  appts[3] = { id: 3, shop_id: 2, status: "cancelled" }; // foreign target
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1" }, // own resource; no body — the finding targets the :id
    exploit: { method: "PATCH", path: "/api/appointments/2" }, // guessed id, no body
    check: idorFieldCheck,
    rationale: "patching another shop's appointment succeeds",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed"); // the value came from the probed id 2, not the same-status baseline
  assert.match(f.verification!.summary, /status changed from "cancelled" to "completed"/);
  assert.equal(appts[3].status, "cancelled"); // restored
});

test("IDOR write: abort-before-write — a body field the snapshot does not return is never written", async () => {
  resetAppts();
  for (const a of Object.values(appts)) a.status = "booked"; // no probed row offers a differing status to harvest
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1" },
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { notes: "pwned" } }, // "notes" is absent from the snapshot
    check: idorFieldCheck,
    rationale: "patching another shop's appointment succeeds",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /no field returned by the snapshot of \/api\/appointments\/3 could be changed, so no write was performed/);
  assert.deepEqual(apptLog.filter((l) => l.startsWith("PATCH")), [], "no mutation was sent");
});

// ---- patch proof --------------------------------------------------------------------------------

const twoRows = JSON.stringify({ appointments: [{ shop_id: 1 }, { shop_id: 1 }] });
const noRows = JSON.stringify({ appointments: [] });
const vulnerableFindByShop = "function findByShop(shopId, status) {\n  return 'VULNERABLE ' + status;\n}\nmodule.exports = { findByShop };\n";
const safePatch = "function findByShop(shopId, status) {\n  return 'SAFE';\n}";

/** A fake "patched server" answering every request with `body`, after `inspect` looks at the patched copy. */
function fakePatchedServer(body: string, inspect: (copyDir: string) => void = () => {}) {
  return async (copyDir: string) => {
    inspect(copyDir);
    const patched = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
    });
    await new Promise<void>((r) => patched.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(patched.address() as AddressInfo).port}`;
    return { target: new Target({ url }), stop: () => new Promise<void>((r) => patched.close(() => r())) };
  };
}

/** The appointments PoC plus the benign response the unpatched target gave, which a patched copy must reproduce. */
const appointmentsPoc = (originalBody = twoRows) => ({
  baseline: { method: "GET", path: "/api/appointments", query: { status: "booked" } },
  exploit: { method: "GET", path: "/api/appointments", query: { status: "' OR '1'='1" } },
  check: { type: "more-rows" as const, field: "appointments" },
  originalBaseline: { status: 200, body: originalBody },
});

/** A throwaway project with the vulnerable sink at db/appointments.js. */
function projectWithSink(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "flowcheck-proj-"));
  mkdirSync(path.join(dir, "db"), { recursive: true });
  writeFileSync(path.join(dir, "db", "appointments.js"), vulnerableFindByShop);
  return dir;
}

test("sameResponse: same status and body (JSON key order ignored) match; a status or row change does not", () => {
  const res = (body: string, status = 200) => ({ status, body });
  assert.equal(sameResponse(res('{"a":1,"b":[1,2]}'), res('{ "b": [1, 2], "a": 1 }')).success, true);
  assert.equal(sameResponse(res("plain text"), res("plain text\n")).success, true);
  assert.equal(sameResponse(res(twoRows), res(twoRows, 500)).success, false);
  const fewer = sameResponse(res(twoRows), res(JSON.stringify({ appointments: [{ shop_id: 1 }] })));
  assert.equal(fewer.success, false);
  assert.match(fewer.detail, /1 row\(s\), originally 2/);
  assert.equal(emptyResult(res(noRows)), true);
  assert.equal(emptyResult(res("")), true);
  assert.equal(emptyResult(res('{"total":0,"items":[]}')), false);
  assert.equal(emptyResult(res(twoRows)), false);
});

test("patch proof: a named-function patch is applied; exploit blocked and benign response unchanged reports 'blocked'", async () => {
  const projectDir = projectWithSink();
  let appliedSource = "";
  // The patched copy answers the exploit and the benign request with the benign response the unpatched target gave.
  const start = fakePatchedServer(twoRows, (copy) => {
    appliedSource = readFileSync(path.join(copy, "db", "appointments.js"), "utf8");
  });
  const result = await verifyPatch({ projectDir, start })({ ...sqliFinding, suggestedPatch: safePatch }, appointmentsPoc());
  rmSync(projectDir, { recursive: true, force: true });

  assert.match(appliedSource, /return 'SAFE'/); // the patch reached the copy
  assert.equal(result?.outcome, "blocked");
  assert.match(result!.summary, /same response as before the patch/);
  assert.doesNotMatch(result!.summary, /carried no data/);
});

test("patch proof: exploit blocked but the benign response changed reports 'breaks-route', not 'blocked'", async () => {
  const projectDir = projectWithSink();
  // The patched copy returns no rows for anything: the exploit no longer wins, but the benign request lost its data too.
  const result = await verifyPatch({ projectDir, start: fakePatchedServer(noRows) })({ ...sqliFinding, suggestedPatch: safePatch }, appointmentsPoc());
  rmSync(projectDir, { recursive: true, force: true });

  assert.equal(result?.outcome, "breaks-route");
  assert.match(result!.summary, /0 row\(s\), originally 2/);
});

test("patch proof: a matching but empty benign response is 'blocked' with a note that it carried no data", async () => {
  const projectDir = projectWithSink();
  const result = await verifyPatch({ projectDir, start: fakePatchedServer(noRows) })({ ...sqliFinding, suggestedPatch: safePatch }, appointmentsPoc(noRows));
  rmSync(projectDir, { recursive: true, force: true });

  assert.equal(result?.outcome, "blocked");
  assert.match(result!.summary, /carried no data/);
});

test("patch proof: copies the runnable project root and resolves the sink under the scanned subtree", async () => {
  // A repo whose package.json is at the root, but only its server/ subtree was scanned (sourceRoot = server).
  const projectDir = mkdtempSync(path.join(tmpdir(), "flowcheck-root-"));
  writeFileSync(path.join(projectDir, "package.json"), '{ "name": "app", "scripts": { "start": "node server/index.js" } }\n');
  mkdirSync(path.join(projectDir, "server", "db"), { recursive: true });
  writeFileSync(path.join(projectDir, "server", "db", "appointments.js"), vulnerableFindByShop);
  let appliedSource = "";
  let copyHadPackageJson = false;

  const start = fakePatchedServer(twoRows, (copy) => {
    copyHadPackageJson = existsSync(path.join(copy, "package.json")); // the runnable root was copied, not just the subtree
    appliedSource = readFileSync(path.join(copy, "server", "db", "appointments.js"), "utf8");
  });
  const prover = verifyPatch({ projectDir, sourceRoot: path.join(projectDir, "server"), start });
  const finding: Finding = { ...sqliFinding, file: "routes/appointments.js", sinkFile: "db/appointments.js", suggestedPatch: safePatch };
  const result = await prover(finding, appointmentsPoc());
  rmSync(projectDir, { recursive: true, force: true });

  assert.equal(copyHadPackageJson, true);
  assert.match(appliedSource, /return 'SAFE'/); // the patch reached the right file inside the subtree
  assert.equal(result?.outcome, "blocked");
});

test("patch proof: an inline-handler patch (no named function) reports 'not-attempted'", async () => {
  const projectDir = mkdtempSync(path.join(tmpdir(), "flowcheck-proj2-"));
  mkdirSync(path.join(projectDir, "routes"), { recursive: true });
  writeFileSync(path.join(projectDir, "routes", "shops.js"), "// handler\n");
  let started = false;
  const prover = verifyPatch({ projectDir, start: async () => { started = true; throw new Error("should not start"); } });
  const finding: Finding = { ...idorFinding, file: "routes/shops.js", sinkFile: "routes/shops.js", suggestedPatch: "router.get('/:shopId/revenue', (req, res) => {});" };
  const result = await prover(finding, {
    baseline: { method: "GET", path: "/x" },
    exploit: { method: "GET", path: "/y" },
    check: { type: "status-unblocked" },
    originalBaseline: { status: 403, body: "" },
  });
  rmSync(projectDir, { recursive: true, force: true });
  assert.equal(result?.outcome, "not-attempted");
  assert.equal(started, false);
});

// ---- Fix B: honest body-diff oracle -------------------------------------------------------------

test("body-diff confirms when the exploit body shows a server success phrase the baseline body lacks", () => {
  const baseline = { status: 200, body: "<script>alert('wrong password'); location.href='/login';</script>", path: "/auth/login", sent: '{"username":"a","password":"b"}' };
  const exploit = { status: 200, body: "<script>alert('login success! welcome'); location.href='/';</script>", path: "/auth/login", sent: '{"username":"\\u0027 OR \\u00271\\u0027=\\u00271 -- ","password":"x"}' };
  const r = evaluate({ type: "body-diff", indicator: "login success" }, baseline, exploit);
  assert.equal(r.success, true);
  assert.match(r.detail, /server success phrase/);
});

test("body-diff does NOT confirm on a trivial difference: phrase in both, an echo of the request, a volatile token, or an empty baseline", () => {
  const base = { status: 200, body: "hello world", path: "/x", sent: "" };
  // present in both responses — not a difference the exploit produced
  assert.equal(evaluate({ type: "body-diff", indicator: "world" }, base, { status: 200, body: "world again", path: "/x", sent: "" }).success, false);
  // the "success phrase" is just the exploit's own input reflected back
  const echo = { status: 200, body: "you searched for ZZPWNED", path: "/x?q=ZZPWNED", sent: "" };
  assert.equal(evaluate({ type: "body-diff", indicator: "ZZPWNED" }, base, echo).success, false);
  // volatile indicators (a CSRF token / hash / timestamp) are refused outright
  assert.equal(evaluate({ type: "body-diff", indicator: "a1b2c3d4e5f6a1b2c3d4" }, base, { status: 200, body: "token a1b2c3d4e5f6a1b2c3d4", path: "/x", sent: "" }).success, false);
  assert.equal(evaluate({ type: "body-diff", indicator: "2026-11-01T09:15:42Z" }, base, { status: 200, body: "at 2026-11-01T09:15:42Z", path: "/x", sent: "" }).success, false);
  // nothing to compare against
  assert.equal(evaluate({ type: "body-diff", indicator: "welcome" }, { status: 200, body: "", path: "/x", sent: "" }, { status: 200, body: "welcome", path: "/x", sent: "" }).success, false);
});

// ---- Fix A: session-cookie authentication -------------------------------------------------------

test("session auth: the verifier logs in, captures the Set-Cookie, and sends it on later requests", async () => {
  const seen: { path: string; cookie: string | undefined }[] = [];
  const srv = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/auth/login" && req.method === "POST") {
      res.writeHead(302, { "set-cookie": "connect.sid=s3cr3t; Path=/; HttpOnly", location: "/" });
      return res.end();
    }
    seen.push({ path: url.pathname, cookie: req.headers.cookie });
    const authed = (req.headers.cookie ?? "").includes("connect.sid=s3cr3t");
    if (!authed) { res.writeHead(302, { location: "/auth/login" }); return res.end(); }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ posts: [{ id: 1 }, { id: 2 }] }));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const target = new Target({ url, auth: { kind: "session", path: "/auth/login", body: { username: "admin", password: "x" } } });
    const res = await target.request("GET", "/post");
    assert.equal(res.status, 200, "the protected route was reached with the session cookie, not redirected to login");
    assert.deepEqual(JSON.parse(res.body).posts.length, 2);
    assert.equal(seen[0]?.cookie, "connect.sid=s3cr3t", "the captured cookie was sent on the protected request");
  } finally {
    srv.close();
  }
});

test("session auth: a login that sets no cookie is a clear configuration error, not a silent miss", async () => {
  const srv = createServer((_req, res) => { res.writeHead(200); res.end("no cookie here"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const target = new Target({ url, auth: { kind: "session", path: "/auth/login", body: {} } });
    await assert.rejects(() => target.request("GET", "/post"), /set no cookie/);
  } finally {
    srv.close();
  }
});

test("cookie auth: a pre-supplied Cookie header is sent as-is, and the bearer flow is left untouched", async () => {
  let got: string | undefined;
  const srv = createServer((req, res) => { got = req.headers.cookie; res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    await new Target({ url, auth: { kind: "cookie", cookie: "sid=abc; theme=dark" } }).request("GET", "/x");
    assert.equal(got, "sid=abc; theme=dark");
    got = undefined;
    await new Target({ url, auth: { kind: "token", token: "t1" } }).request("GET", "/x");
    assert.equal(got, undefined, "a bearer target never sends a cookie");
  } finally {
    srv.close();
  }
});

// ---- write-IDOR proves on the real ownership field, never the record's own id -------------------

test("IDOR write: uses the detector's ownership field (shop_id), ignoring a PoC that named the primary key", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  // The detector identified shop_id as the scope column; the model's PoC wrongly named `id` (the record's own key).
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id", ownershipField: "shop_id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1", body: { status: "completed" } },
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { status: "cancelled" } }, // id 2 is the caller's OWN shop
    check: { type: "field-differs", field: "id" }, // must be ignored in favour of shop_id
    rationale: "patching another shop's appointment succeeds",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /own shop_id=1/);
  assert.match(f.verification!.summary, /found id 3 owned by shop_id=2/, "crossed the shop boundary — evidence cites shop_id");
  assert.doesNotMatch(f.verification!.summary, /owned by id=/, "never reasons about the record's own id");
  assert.equal(appts[2].status, "completed", "the same-shop id 2 the model guessed was never mutated");
  assert.equal(appts[3].status, "booked", "the foreign record was restored");
});

test("IDOR write: a same-shop record whose id merely differs does NOT falsely confirm (no cross-scope id exists)", async () => {
  // Only shop 1 exists here: ids differ but every shop_id is the caller's own, so there is no cross-scope write to prove.
  appts = { 1: { id: 1, shop_id: 1, status: "booked" }, 2: { id: 2, shop_id: 1, status: "completed" } };
  apptLog.length = 0;
  const before = JSON.stringify(appts);
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id", ownershipField: "shop_id" };
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1", body: { status: "completed" } },
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { status: "cancelled" } },
    check: { type: "field-differs", field: "shop_id" },
    rationale: "x",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /no resource owned by another scope/);
  assert.equal(JSON.stringify(appts), before, "no foreign record existed, so nothing was mutated");
});

test("IDOR write: with no ownership field known, it refuses to confirm or mutate on the record's own id", async () => {
  resetAppts();
  const before = JSON.stringify(appts);
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-862", httpRoute: "PATCH /api/appointments/:id" }; // no ownershipField
  const poc = {
    baseline: { method: "PATCH", path: "/api/appointments/1", body: { status: "completed" } },
    exploit: { method: "PATCH", path: "/api/appointments/2", body: { status: "cancelled" } },
    check: { type: "field-differs", field: "id" }, // the route's own path parameter — the record's primary key
    rationale: "x",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /the record's own id is not an ownership field/);
  assert.equal(JSON.stringify(appts), before, "no mutating request was sent");
});

test("findOwnerField matches an ownership column across snake_case and camelCase response keys", () => {
  assert.equal(findOwnerField({ shopId: 2 }, "shop_id"), 2);
  assert.equal(findOwnerField({ shop_id: 2 }, "shopId"), 2);
  assert.equal(findOwnerField({ data: { owner_id: 7 } }, "owner_id"), 7);
  assert.equal(findOwnerField({ id: 5 }, "shop_id"), undefined);
});

// ---- read-IDOR proves on the ownership field, never the primary key -----------------------------

test("IDOR read: confirms on the ownership field (shop_id) even when the PoC named the primary key", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id", ownershipField: "shop_id" };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" }, // own, shop_id 1
    exploit: { method: "GET", path: "/api/appointments/3" }, // shop_id 2 — a different shop
    check: { type: "field-differs", field: "id" }, // model named the record's own key; must be ignored
    rationale: "reading another shop's appointment",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "confirmed");
  assert.match(f.verification!.summary, /shop_id=2.*vs the baseline's 1/, "evidence cites the ownership field, not the id");
});

test("IDOR read: a different primary key within the SAME scope does NOT falsely confirm", async () => {
  // Only shop 1 exists: ids differ but every shop_id is the caller's own, so no cross-scope read can be proved.
  appts = { 1: { id: 1, shop_id: 1, status: "booked" }, 2: { id: 2, shop_id: 1, status: "completed" } };
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id", ownershipField: "shop_id" };
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" },
    exploit: { method: "GET", path: "/api/appointments/2" }, // different id, SAME shop_id
    check: { type: "field-differs", field: "shop_id" },
    rationale: "x",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "unverified", "same shop_id on both — not a cross-scope read");
});

test("IDOR read: with no ownership field known, a differing primary key alone does not confirm", async () => {
  resetAppts();
  const target = new Target({ url: base, auth: idorToken });
  const finding: Finding = { ...idorFinding, cwe: "CWE-639", httpRoute: "GET /api/appointments/:id" }; // no ownershipField
  const poc = {
    baseline: { method: "GET", path: "/api/appointments/1" },
    exploit: { method: "GET", path: "/api/appointments/3" },
    check: { type: "field-differs", field: "id" }, // the route's path parameter — the record's own id
    rationale: "x",
  };
  const f = await verifyFinding(finding, target, { complete: completeWith(poc), probe: { range: 20 } });
  assert.equal(f.confidence, "unverified");
  assert.match(f.verification!.summary, /not proof that the record belongs to another scope/);
});
