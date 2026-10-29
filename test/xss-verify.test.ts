// Offline tests for XSS execution-proof orchestration: plan parsing, the marker oracle, and the stored write/restore
// discipline — driven by in-memory loopback servers and a fetch-based fake browser, so no real Chrome is needed.
// (The real headless-browser mechanics are exercised by scripts/xss-exec-proof-live.ts, which is not part of npm test.)
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, test } from "node:test";
import { Target } from "../src/engine/verify/target.js";
import {
  buildXssPocPrompt,
  isXssFinding,
  MARKER_PLACEHOLDER,
  parseXssPlan,
  proveXss,
  type BrowserLike,
  type Finding,
} from "../src/engine/verify/index.js";

const finding = (type: string): Finding => ({ type, cwe: "CWE-79", severity: "high", file: "x", sourceLine: 1, sinkLine: 1, taintPath: ["src", "sink"], explanation: "e", suggestedPatch: "p", confidence: "suspected" });
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const PAYLOAD = `<img src=x onerror="window.__fcDetect('${MARKER_PLACEHOLDER}')">`;
const servers: http.Server[] = [];
after(() => servers.forEach((s) => s.close()));

async function listen(h: http.RequestListener): Promise<string> {
  const s = http.createServer(h);
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
}

/**
 * A fake browser that stands in for headless Chrome without running JS: it fetches the URL and reports the marker
 * only when the executing payload survived into the HTML verbatim (an unescaped onerror/script). Escaped output does
 * not match, so the oracle stays honest. (It cannot run client-side fetch+render; that path is in the live script.)
 */
class FetchBrowser implements BrowserLike {
  loads: string[] = [];
  async load(url: string): Promise<{ url: string; status: number | null; marker: string | null }> {
    this.loads.push(url);
    const res = await fetch(url);
    const html = await res.text();
    const m = /on\w+="window\.__fcDetect\('(FCX-[^']+)'\)"/.exec(html) ?? /<script>window\.__fcDetect\('(FCX-[^']+)'\)<\/script>/.exec(html);
    return { url, status: res.status, marker: m ? m[1] : null };
  }
}

// ---- plan parsing / prompt --------------------------------------------------------------------

test("isXssFinding matches CWE-79 and XSS types, not others", () => {
  assert.ok(isXssFinding(finding("Cross-Site Scripting (Stored)")));
  assert.ok(isXssFinding({ ...finding("Anything"), cwe: "CWE-79" }));
  assert.ok(!isXssFinding({ ...finding("SQL Injection"), cwe: "CWE-89" }));
});

test("the PoC prompt carries the marker placeholder and the detector contract", () => {
  const p = buildXssPocPrompt(finding("Cross-Site Scripting (Reflected)"));
  assert.match(p, new RegExp(MARKER_PLACEHOLDER.replace(/[$]/g, "\\$&")));
  assert.match(p, /window\.__fcDetect/);
  assert.match(p, /This is REFLECTED XSS/);
  assert.match(buildXssPocPrompt(finding("Cross-Site Scripting (Stored)")), /This is STORED XSS across two requests/);
});

test("parseXssPlan reads reflected and stored plans; a payload missing the marker falls back to a working one", () => {
  const reflected = parseXssPlan('[{"kind":"reflected","render":{"path":"/book/1/search","param":"q","in":"query"},"payload":"<svg onload=\\"window.__fcDetect(\'__FCMARK__\')\\">","benign":"hi"}]');
  assert.deepEqual(reflected, { kind: "reflected", render: { path: "/book/1/search", param: "q", in: "query", authenticated: false, client: false }, payload: `<svg onload="window.__fcDetect('__FCMARK__')">`, benign: "hi" });

  const stored = parseXssPlan('[{"kind":"stored","write":{"method":"put","path":"/api/barbers/1/bio","bodyField":"bio"},"render":{"path":"/book/1/barbers/1"},"readBack":{"path":"/api/barbers/1/profile","field":"bio"},"payload":"no marker here","benign":"b"}]');
  assert.equal(stored.kind, "stored");
  if (stored.kind === "stored") {
    assert.equal(stored.write.method, "PUT");
    assert.equal(stored.payload, "no marker here"); // kept verbatim; the working-payload fallback is applied at proof time
  }
  assert.throws(() => parseXssPlan('[{"kind":"stored","render":{"path":"/x"}}]'), /schema/);
});

test("a marker-less model payload still proves: proveXss substitutes a working payload with the fresh marker", async () => {
  const base = await listen((req, res) => {
    const q = new URL(req.url!, "http://x").searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><h1>results for ${q}</h1>`);
  });
  const plan = parseXssPlan('[{"kind":"reflected","render":{"path":"/search","param":"q","in":"query"},"payload":"alert(1)","benign":"hi"}]');
  const proof = await proveXss(finding("Cross-Site Scripting (Reflected)"), plan, new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "confirmed");
});

// ---- reflected proof --------------------------------------------------------------------------

test("reflected: confirmed when the payload executes and the benign baseline does not", async () => {
  const base = await listen((req, res) => {
    const q = new URL(req.url!, "http://x").searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><h1>results for ${q}</h1>`);
  });
  const browser = new FetchBrowser();
  const plan = parseXssPlan(`[{"kind":"reflected","render":{"path":"/search","param":"q","in":"query"},"payload":${JSON.stringify(PAYLOAD)},"benign":"hello"}]`);
  const proof = await proveXss(finding("Cross-Site Scripting (Reflected)"), plan, new Target({ url: base }), { browser });
  assert.equal(proof.kind, "confirmed");
  assert.match(proof.verification!.exploit!.responseExcerpt, /payload executed \(marker FCX-/);
  assert.match(proof.verification!.baseline!.responseExcerpt, /no marker/);
  assert.equal(browser.loads.length, 2);
});

test("reflected: structural path params are filled from the route template with a valid id, not the model's string", async () => {
  // Mimics the fixture: a non-numeric :shopId 404s and never renders; a numeric one renders the reflected q.
  const base = await listen((req, res) => {
    const m = /^\/book\/([^/]+)\/search$/.exec(new URL(req.url!, "http://x").pathname);
    if (!m || !/^\d+$/.test(m[1])) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    const q = new URL(req.url!, "http://x").searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><h1>results for ${q}</h1>`);
  });
  const browser = new FetchBrowser();
  // The model's render.path has a bad non-numeric shopId; the authoritative route template drives the real path.
  const plan = parseXssPlan(`[{"kind":"reflected","render":{"path":"/book/shop123/search","param":"q","in":"query"},"payload":${JSON.stringify(PAYLOAD)},"benign":"hello"}]`);
  const f = { ...finding("Cross-Site Scripting (Reflected)"), httpRoute: "GET /book/:shopId/search" };
  const proof = await proveXss(f, plan, new Target({ url: base }), { browser });
  assert.equal(proof.kind, "confirmed");
  assert.ok(browser.loads.every((u) => u.includes("/book/1/search")), `path params filled with a valid id; loaded ${browser.loads.join(", ")}`);
});

test("reflected: NOT confirmed when the reflection is HTML-escaped (the escaped-output discrimination)", async () => {
  const base = await listen((req, res) => {
    const q = new URL(req.url!, "http://x").searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><h1>results for ${esc(q)}</h1>`);
  });
  const plan = parseXssPlan(`[{"kind":"reflected","render":{"path":"/search","param":"q","in":"query"},"payload":${JSON.stringify(PAYLOAD)},"benign":"hello"}]`);
  const proof = await proveXss(finding("Cross-Site Scripting (Reflected)"), plan, new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "unverified");
  assert.match((proof as { reason: string }).reason, /payload did not execute/);
});

// ---- stored proof: write, render, restore -----------------------------------------------------

/** An in-memory bio store with a PUT writer, a JSON read-back, and an HTML render (optionally escaped). */
function bioServer(opts: { escape?: boolean; alwaysPayload?: boolean; readBackOmitsField?: boolean; profileReturnsField?: boolean } = {}) {
  const state = { bio: "the original bio", writes: [] as string[] };
  const handler: http.RequestListener = (req, res) => {
    const u = new URL(req.url!, "http://x");
    if (req.method === "PUT" && u.pathname === "/bio") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        state.bio = JSON.parse(b || "{}").bio ?? "";
        state.writes.push(state.bio);
        res.end("{}");
      });
      return;
    }
    if (u.pathname === "/json") {
      res.setHeader("content-type", "application/json");
      // readBackOmitsField mimics a route that returns the resource WITHOUT the written field (e.g. a summary route).
      res.end(JSON.stringify({ barber: opts.readBackOmitsField ? { name: "x" } : { bio: state.bio } }));
      return;
    }
    if (u.pathname === "/profile") {
      // A sibling detail route that DOES return the field; the tool derives it from the write path.
      if (!opts.profileReturnsField) {
        res.statusCode = 404;
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ barber: { bio: state.bio } }));
      return;
    }
    if (u.pathname === "/page") {
      const shown = opts.alwaysPayload ? `<img src=x onerror="window.__fcDetect('FCX-sticky')">` : opts.escape ? esc(state.bio) : state.bio;
      res.setHeader("content-type", "text/html");
      res.end(`<!doctype html><div class=card>${shown}</div>`);
      return;
    }
    res.statusCode = 404;
    res.end();
  };
  return { state, handler };
}

const storedPlan = (base = "/page") =>
  parseXssPlan(`[{"kind":"stored","write":{"method":"PUT","path":"/bio","bodyField":"bio"},"render":{"path":${JSON.stringify(base)}},"readBack":{"path":"/json","field":"bio"},"payload":${JSON.stringify(PAYLOAD)},"benign":"a benign bio"}]`);

test("stored: confirmed when the stored payload renders and executes, and the original value is restored", async () => {
  const srv = bioServer();
  const base = await listen(srv.handler);
  const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), storedPlan(), new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "confirmed");
  assert.match(proof.verification!.summary, /The original value was restored\./);
  assert.equal(srv.state.bio, "the original bio", "the bio is restored to its snapshot");
  assert.deepEqual(srv.state.writes.at(-1), "the original bio", "the last write restores the original");
  assert.equal(srv.state.writes.length, 3, "payload write, benign baseline write, restore write");
});

test("stored: NOT confirmed when the render escapes the stored value; still restored", async () => {
  const srv = bioServer({ escape: true });
  const base = await listen(srv.handler);
  const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), storedPlan(), new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "unverified");
  assert.equal(srv.state.bio, "the original bio");
});

test("stored: NOT confirmed when the baseline also executes (execution not attributable to the payload)", async () => {
  const srv = bioServer({ alwaysPayload: true }); // the page always contains an executing marker, regardless of the stored value
  const base = await listen(srv.handler);
  const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), storedPlan(), new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "unverified");
  assert.match((proof as { reason: string }).reason, /baseline also executed/);
});

test("stored: snapshot recovers via a derived read-back route when the model's omits the field — confirmed and restored", async () => {
  // The model's read-back (/json) omits the field, but the tool derives /profile from the write path, which returns it.
  const srv = bioServer({ readBackOmitsField: true, profileReturnsField: true });
  const base = await listen(srv.handler);
  const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), storedPlan(), new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "confirmed");
  assert.match(proof.verification!.summary, /The original value was restored\./);
  assert.equal(srv.state.bio, "the original bio", "restored to the snapshot taken via the derived route");
});

test("stored: abort-before-write — a snapshot that cannot read the field writes NOTHING and leaves the fixture clean", async () => {
  const srv = bioServer({ readBackOmitsField: true }); // readBack returns the resource without the written field
  const base = await listen(srv.handler);
  const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), storedPlan(), new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "unverified");
  assert.match((proof as { reason: string }).reason, /could not snapshot the target field .* so no payload was written/);
  assert.equal(srv.state.writes.length, 0, "no write happened — the fixture was never mutated");
  assert.equal(srv.state.bio, "the original bio");
});

test("stored: the traced write route overrides a model write path that drops a segment — confirmed via the real routes", async () => {
  // Mirrors the live barber app: PUT /api/barbers/:id/bio writes, GET /api/barbers/:id omits bio, /:id/profile has it.
  const state = { bio: "the original bio", writes: [] as string[] };
  const base = await listen((req, res) => {
    const u = new URL(req.url!, "http://x");
    const json = (o: unknown) => (res.setHeader("content-type", "application/json"), res.end(JSON.stringify(o)));
    if (req.method === "PUT" && u.pathname === "/api/barbers/2/bio") {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        state.bio = JSON.parse(b || "{}").bio ?? "";
        state.writes.push(u.pathname);
        json({});
      });
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/barbers/2") return json({ barber: { id: 2, name: "x" } });
    if (req.method === "GET" && u.pathname === "/api/barbers/2/profile") return json({ barber: { id: 2, bio: state.bio } });
    if (u.pathname === "/book/1/barbers/2") return (res.setHeader("content-type", "text/html"), res.end(`<!doctype html><p>${state.bio}</p>`));
    res.statusCode = 404;
    res.end();
  });
  const plan = parseXssPlan(
    `[{"kind":"stored","write":{"method":"PUT","path":"/api/barbers/2","bodyField":"bio"},"render":{"path":"/book/1/barbers/2"},"readBack":{"path":"/api/barbers/2","field":"bio"},"payload":${JSON.stringify(PAYLOAD)},"benign":"a benign bio"}]`,
  );
  const f = { ...finding("Cross-Site Scripting (Stored)"), writeRoute: "PUT /api/barbers/:id/bio" };
  const proof = await proveXss(f, plan, new Target({ url: base }), { browser: new FetchBrowser() });
  assert.equal(proof.kind, "confirmed");
  assert.match(proof.verification!.summary, /written via PUT \/api\/barbers\/2\/bio .* The original value was restored\./);
  assert.deepEqual(state.writes, ["/api/barbers/2/bio", "/api/barbers/2/bio", "/api/barbers/2/bio"], "every write went to the traced route, the model's id kept");
  assert.equal(state.bio, "the original bio");
});

test("the stored PoC prompt names the traced write route", () => {
  const p = buildXssPocPrompt({ ...finding("Cross-Site Scripting (Stored)"), writeRoute: "PUT /api/barbers/:id/bio" });
  assert.match(p, /The write route traced in the code is PUT \/api\/barbers\/:id\/bio — use that exact method and path/);
});
