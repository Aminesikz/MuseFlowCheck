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
  parsePoc,
  sameResponse,
  Target,
  TargetError,
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

before(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const authed = (req.headers.authorization ?? "") === "Bearer tenant-1";
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/api/auth/login") return json(200, { token: "tenant-1" });
    if (!authed) return json(401, { error: "unauthorized" });
    if (url.pathname === "/api/appointments") {
      const status = url.searchParams.get("status") ?? "";
      const injected = /'|union|or\s+1=1/i.test(status); // the "vulnerable" query dumps all shops
      return json(200, { appointments: injected ? [{ shop_id: 1 }, { shop_id: 1 }, { shop_id: 2 }, { shop_id: 2 }] : [{ shop_id: 1 }, { shop_id: 1 }] });
    }
    const revenue = /^\/api\/shops\/(\d+)\/revenue$/.exec(url.pathname); // IDOR: returns whatever shop is asked for
    if (revenue) return json(200, { revenue: { shopId: Number(revenue[1]), totalCents: 1000 * Number(revenue[1]) } });
    return json(404, { error: "not found" });
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
