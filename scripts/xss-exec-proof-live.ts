// Live XSS execution-proof check against real headless Chrome. NOT part of `npm test` — it needs a Chrome binary
// (set FC_CHROME to override the default path). It spins up throwaway loopback servers that mimic the vulnerable and
// safe shapes, then proves each with the real ExecBrowser, confirming the oracle only fires on genuine execution and
// that a stored proof restores what it wrote.
import http from "node:http";
import type { AddressInfo } from "node:net";
import assert from "node:assert/strict";
import { ExecBrowser } from "../src/engine/verify/browser.js";
import { Target } from "../src/engine/verify/target.js";
import { proveXss, type BrowserLike, type XssPlan } from "../src/engine/verify/xss.js";
import type { Finding } from "../src/types/index.js";

const CHROME = process.env.FC_CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PAYLOAD = `<img src=x onerror="window.__fcDetect('__FCMARK__')">`;
const finding = (type: string): Finding => ({ type, cwe: "CWE-79", severity: "high", file: "x", sourceLine: 1, sinkLine: 1, taintPath: ["a", "b"], explanation: "e", suggestedPatch: "p", confidence: "suspected" });
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

async function listen(h: http.RequestListener): Promise<{ base: string; close: () => void }> {
  const s = http.createServer(h);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return { base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, close: () => s.close() };
}

/** Reads a JSON {bio} store with a PUT writer and an HTML render page; optionally escapes the render. */
function bioServer(escapeRender: boolean, initial = "original bio") {
  let bio = initial;
  return {
    get bio() {
      return bio;
    },
    handler: ((req, res) => {
      const u = new URL(req.url!, "http://x");
      res.setHeader("access-control-allow-origin", "*");
      res.setHeader("access-control-allow-headers", "authorization, content-type");
      if (req.method === "OPTIONS") {
        res.statusCode = 204;
        res.end();
        return;
      }
      if (req.method === "PUT" && u.pathname === "/bio") {
        let b = "";
        req.on("data", (c) => (b += c));
        req.on("end", () => {
          bio = JSON.parse(b || "{}").bio ?? "";
          res.end("{}");
        });
        return;
      }
      if (u.pathname === "/json") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ bio, auth: req.headers.authorization ?? null }));
        return;
      }
      if (u.pathname === "/page") {
        res.setHeader("content-type", "text/html");
        res.end(`<!doctype html><div class=card>${escapeRender ? esc(bio) : bio}</div>`);
        return;
      }
      res.statusCode = 404;
      res.end();
    }) as http.RequestListener,
  };
}

async function reflected(browser: BrowserLike, escapeRender: boolean) {
  const srv = await listen((req, res) => {
    const q = new URL(req.url!, "http://x").searchParams.get("q") ?? "";
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><h1>results for ${escapeRender ? esc(q) : q}</h1>`);
  });
  try {
    const plan: XssPlan = { kind: "reflected", render: { path: "/search", param: "q", in: "query", authenticated: false, client: false }, payload: PAYLOAD, benign: "hello world" };
    return await proveXss(finding("Cross-Site Scripting (Reflected)"), plan, new Target({ url: srv.base }), { browser });
  } finally {
    srv.close();
  }
}

async function storedServer(browser: BrowserLike) {
  const store = bioServer(false);
  const srv = await listen(store.handler);
  try {
    const plan: XssPlan = { kind: "stored", write: { method: "PUT", path: "/bio", bodyField: "bio" }, render: { path: "/page", authenticated: false, client: false }, readBack: { path: "/json", field: "bio" }, payload: PAYLOAD, benign: "benign bio" };
    const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), plan, new Target({ url: srv.base }), { browser });
    return { proof, restored: store.bio === "original bio" };
  } finally {
    srv.close();
  }
}

/** FC-08 shape: the render is a client app that reads a token from localStorage, fetches the bio, and inserts it as HTML. */
async function storedClient() {
  const store = bioServer(false);
  const api = await listen(store.handler);
  const client = await listen((_req, res) => {
    res.setHeader("content-type", "text/html");
    res.end(`<!doctype html><div id=app></div><script>
      (async () => {
        const t = localStorage.getItem('fc_token');
        const r = await fetch(${JSON.stringify(api.base)} + '/json', { headers: t ? { Authorization: 'Bearer ' + t } : {} });
        document.getElementById('app').innerHTML = (await r.json()).bio;
      })();
    </script>`);
  });
  const browser = await ExecBrowser.launch({ executablePath: CHROME }, { token: "tenant-1-token", via: { kind: "localStorage", key: "fc_token" } });
  try {
    const plan: XssPlan = { kind: "stored", write: { method: "PUT", path: "/bio", bodyField: "bio" }, render: { path: "/", authenticated: true, client: true }, readBack: { path: "/json", field: "bio" }, payload: PAYLOAD, benign: "benign" };
    const proof = await proveXss(finding("Cross-Site Scripting (Stored)"), plan, new Target({ url: api.base }), { browser, clientBase: client.base });
    return { proof, restored: store.bio === "original bio" };
  } finally {
    await browser.close();
    api.close();
    client.close();
  }
}

async function main() {
  const browser = await ExecBrowser.launch({ executablePath: CHROME });
  try {
    const refl = await reflected(browser, false);
    assert.equal(refl.kind, "confirmed", "reflected should confirm");
    console.log("✓ reflected (FC-06 shape):", refl.kind, "—", refl.verification!.summary);

    const safe = await reflected(browser, true);
    assert.equal(safe.kind, "unverified", "escaped reflection must not confirm");
    console.log("✓ reflected-escaped (SAFE):", safe.kind, "(correctly not confirmed — escaped output did not execute)");

    const stored = await storedServer(browser);
    assert.equal(stored.proof.kind, "confirmed", "stored should confirm");
    assert.ok(stored.restored, "stored value must be restored");
    console.log("✓ stored server-rendered (FC-07 shape):", stored.proof.kind, "— restored:", stored.restored);
  } finally {
    await browser.close();
  }
  const client = await storedClient();
  assert.equal(client.proof.kind, "confirmed", "client-rendered stored should confirm");
  assert.ok(client.restored, "stored value must be restored");
  console.log("✓ stored client-rendered (FC-08 shape):", client.proof.kind, "— token injected, fetched with auth, DOM sink fired; restored:", client.restored);

  console.log("\nALL LIVE CHECKS PASSED");
}

main().catch((e) => {
  console.error("LIVE CHECK FAILED:", e instanceof Error ? e.message : e);
  process.exit(1);
});
