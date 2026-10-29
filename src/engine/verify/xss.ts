// Execution-based proof for XSS findings: render the vulnerable page in a headless browser and confirm a payload's
// JavaScript actually runs, baseline-compared. Confirmed only when a fresh unique marker is reported by the EXPLOIT
// load and NOT by the BENIGN baseline load — the same oracle honesty as the SQLi/IDOR proofs. Every request and page
// load targets the configured loopback host; a stored proof restores what it writes, as the IDOR write-proof does.
import { randomUUID } from "node:crypto";
import type { Finding, Verification } from "../../types/index.js";
import { extractJsonArray, FindingParseError } from "../parse.js";
import { DETECT_GLOBAL, type LoadResult } from "./browser.js";
import { evidence } from "./evidence.js";
import { findField, parse } from "./evaluate.js";
import { assertLocalTarget, type Target, type TargetResponse } from "./target.js";

/** The token a plan's payload must contain; the tool swaps in a fresh per-run marker, so markers are never reused. */
export const MARKER_PLACEHOLDER = "__FCMARK__";
/** A built-in payload used when the model's payload omits the marker/detector contract (two execution vectors). */
const FALLBACK_PAYLOAD = `<img src=x onerror="window.${DETECT_GLOBAL}('${MARKER_PLACEHOLDER}')"><script>window.${DETECT_GLOBAL}('${MARKER_PLACEHOLDER}')</script>`;

export function isXssFinding(finding: Finding): boolean {
  return finding.cwe === "CWE-79" || /cross-site scripting|xss/i.test(finding.type);
}
const isStored = (finding: Finding): boolean => /stored/i.test(finding.type);

interface RenderTarget {
  path: string;
  /** Load through the browser-auth token (a client app that holds the token client-side). Server pages are public. */
  authenticated: boolean;
  /** Load from the client origin instead of the API target (a React/SPA view). */
  client: boolean;
}

/** The reflected plan: where the payload goes in the request that renders it. */
interface ReflectedPlan {
  kind: "reflected";
  render: RenderTarget & { param: string; in: "query" | "path" };
  payload: string;
  benign: string;
}

/** The stored plan: the write request, the page that renders the stored value, and how to read it back to restore it. */
interface StoredPlan {
  kind: "stored";
  write: { method: string; path: string; bodyField: string };
  render: RenderTarget;
  readBack: { path: string; field: string };
  payload: string;
  benign: string;
}

export type XssPlan = ReflectedPlan | StoredPlan;
export type XssProof = { kind: "confirmed"; verification: Verification } | { kind: "unverified"; reason: string; verification?: Verification };

/** The browser capability the proof needs: load a local URL and report whether a payload executed. */
export interface BrowserLike {
  load(url: string, authenticated?: boolean): Promise<LoadResult>;
}

/** Dependencies for the XSS proof: a launched browser and the client origin (for SPA-rendered sinks). */
export interface XssProofDeps {
  browser: BrowserLike;
  /** Base URL of the client app, when the rendering sink is in browser code. Must be loopback. */
  clientBase?: string;
}

// ---- prompt / parsing -------------------------------------------------------------------------

export function buildXssPocPrompt(finding: Finding, identityHint?: string): string {
  const stored = isStored(finding);
  const detector = `window.${DETECT_GLOBAL}('${MARKER_PLACEHOLDER}')`;
  const common = `You are proving one Cross-Site Scripting finding against a running LOCAL test instance, by making a real browser execute an injected payload. A headless browser will load the rendering page; a payload that runs must call ${detector}. Use the literal token ${MARKER_PLACEHOLDER} inside the payload — the tool replaces it with a fresh unique value and detects the call. Give a payload that runs in the context the finding lands in (e.g. an element-content or attribute context): an event-handler vector like <img src=x onerror="${detector}"> is reliable because inserted <script> elements do not execute. Also give a benign, non-executing value for the baseline.

FINDING
- ${finding.type} (${finding.cwe}) — source ${finding.file}:${finding.sourceLine}; sink ${finding.sinkFile ?? finding.file}:${finding.sinkLine}
- HTTP route: ${finding.httpRoute ?? "(not given)"}
- taint path:\n${finding.taintPath.map((h) => `    ${h}`).join("\n")}
- why exploitable: ${finding.explanation}`;

  if (!stored) {
    return `${common}

This is REFLECTED XSS: the payload goes in a request parameter and comes straight back in the rendered page.
Return ONLY a JSON array with one object — no prose, no fences:
[{
  "kind": "reflected",
  "render": {"path": "/full/route/path", "param": "<the query or path param the source reads>", "in": "query", "authenticated": false, "client": false},
  "payload": "<the executing payload containing ${MARKER_PLACEHOLDER}>",
  "benign": "<an ordinary non-executing value>"
}]
Build "render.path" from the finding's HTTP route (keep the mount prefix). "in" is "query" for a ?param, "path" for a path segment.`;
  }

  return `${common}

This is STORED XSS across two requests: a WRITE request persists the payload, and a later page renders it. ${identityHint ?? "You have a low-privilege token for one tenant."}${finding.writeRoute ? `\nThe write route traced in the code is ${finding.writeRoute} — use that exact method and path for "write", filling its parameters with the record you own.` : ""}
Return ONLY a JSON array with one object — no prose, no fences:
[{
  "kind": "stored",
  "write":    {"method": "PUT|POST|PATCH", "path": "/the/write/route", "bodyField": "<the body field the source reads, e.g. bio>"},
  "render":   {"path": "/the/page/that/renders/it", "authenticated": <true if that page is a client app needing the token>, "client": <true if it is the React/SPA client, not a server HTML route>},
  "readBack": {"path": "/a/route/that/returns/the/stored/value/as/json", "field": "<json field holding the stored value>"},
  "payload": "<the executing payload containing ${MARKER_PLACEHOLDER}>",
  "benign": "<an ordinary non-executing bio/value>"
}]
The tool snapshots the stored value via readBack BEFORE writing and will NOT write the payload unless that snapshot succeeds. So "readBack" MUST be a route that actually returns the same field you write in "bodyField" — pick a detail/profile route that includes that field, not a list or summary route that omits it. Write to a record you own. For a server-rendered page set client:false, authenticated:false. For the React client view set client:true.`;
}

function asRender(v: unknown): RenderTarget {
  const r = (v ?? {}) as Record<string, unknown>;
  if (typeof r.path !== "string" || !r.path.startsWith("/")) throw new Error('render.path must be a "/..." string');
  return { path: r.path, authenticated: r.authenticated === true, client: r.client === true };
}

export function parseXssPlan(raw: string): XssPlan {
  const items = extractJsonArray(raw);
  if (items.length === 0) throw new FindingParseError("XSS plan was an empty array", raw);
  try {
    const o = items[0] as Record<string, unknown>;
    const payload = typeof o.payload === "string" && o.payload ? o.payload : FALLBACK_PAYLOAD;
    const benign = typeof o.benign === "string" && o.benign ? o.benign : "flowcheck-benign-value";
    if (o.kind === "stored") {
      const w = (o.write ?? {}) as Record<string, unknown>;
      const rb = (o.readBack ?? {}) as Record<string, unknown>;
      if (typeof w.method !== "string" || typeof w.path !== "string" || typeof w.bodyField !== "string") throw new Error("stored.write needs method, path, bodyField");
      if (typeof rb.path !== "string" || typeof rb.field !== "string") throw new Error("stored.readBack needs path, field");
      return { kind: "stored", write: { method: w.method.toUpperCase(), path: w.path, bodyField: w.bodyField }, render: asRender(o.render), readBack: { path: rb.path, field: rb.field }, payload, benign };
    }
    const render = asRender(o.render) as ReflectedPlan["render"];
    const rp = (o.render ?? {}) as Record<string, unknown>;
    if (typeof rp.param !== "string") throw new Error("reflected.render.param is required");
    render.param = rp.param;
    render.in = rp.in === "path" ? "path" : "query";
    return { kind: "reflected", render, payload, benign };
  } catch (err) {
    throw new FindingParseError(`XSS plan does not match the expected schema: ${(err as Error).message}`, raw);
  }
}

/** Replaces the marker placeholder; guarantees the payload actually calls the detector (else uses the fallback). */
function withMarker(payload: string, marker: string): string {
  const p = payload.includes(MARKER_PLACEHOLDER) && payload.includes(DETECT_GLOBAL) ? payload : FALLBACK_PAYLOAD;
  return p.split(MARKER_PLACEHOLDER).join(marker);
}

// ---- proof ------------------------------------------------------------------------------------

const ok = (s: number | null): boolean => s !== null && s >= 200 && s < 300;

/**
 * Ordered read-back routes to snapshot the written field from: the model's own read-back first, then routes derived
 * structurally from the write path — its parent resource, a sibling detail/profile route, and the field as its own
 * GET resource — so a snapshot succeeds even when the model names a route that omits the field. Deduplicated.
 */
function readBackCandidates(plan: StoredPlan): string[] {
  const parent = plan.write.path.replace(/\/[^/]+$/, ""); // /api/x/:id/field -> /api/x/:id
  const candidates = [plan.readBack.path, parent, `${parent}/profile`, `${parent}/details`, plan.write.path];
  return [...new Set(candidates.filter((p) => p.startsWith("/")))];
}

function loadEvidence(load: LoadResult, note: string) {
  return { method: "GET", path: load.url, status: load.status ?? 0, responseExcerpt: note };
}

/** Resolves a render URL against the right origin (API target, or the client app), enforcing loopback. */
function renderUrl(render: RenderTarget, target: Target, clientBase: string | undefined): string {
  const base = render.client ? clientBase : target.base;
  if (!base) throw new FindingParseError("the finding renders in the client app; pass its local URL with --xss-client <url>", "");
  const url = base.replace(/\/$/, "") + render.path;
  assertLocalTarget(url); // defense in depth: a render page is always on a loopback host
  return url;
}

export async function proveXss(finding: Finding, plan: XssPlan, target: Target, deps: XssProofDeps): Promise<XssProof> {
  const marker = `FCX-${randomUUID()}`;
  const payload = withMarker(plan.payload, marker);
  return plan.kind === "reflected"
    ? proveReflected(finding, plan, payload, marker, target, deps)
    : proveStored({ ...plan, write: { ...plan.write, ...tracedWrite(finding, plan) } }, payload, marker, target, deps);
}

// A valid value for a structural path parameter: route ids are numeric, and 1 is the lowest seeded id and the
// authenticated caller's own scope, so it renders a real page. The payload never goes in a structural param.
const PATH_PARAM_ID = "1";

/**
 * The write request from the route Stage 1 traced as the writer, when there is one: its method and path template are
 * authoritative (the model may drop a segment, e.g. "/api/barbers/2" for "/api/barbers/:id/bio"). Each path param
 * takes the model's numeric id at the same position — the record it chose to write — else a valid id.
 */
function tracedWrite(finding: Finding, plan: StoredPlan): { method: string; path: string } {
  const m = /^(\S+)\s+(\/\S*)$/.exec(finding.writeRoute ?? "");
  if (!m) return plan.write;
  const chosen = plan.write.path.split(/[?#]/)[0].split("/");
  const path = m[2]
    .split("/")
    .map((seg, i) => (seg.startsWith(":") ? (/^\d+$/.test(chosen[i] ?? "") ? chosen[i] : PATH_PARAM_ID) : seg))
    .join("/");
  return { method: m[1].toUpperCase(), path };
}

/** The sink route's path template, from the finding's HTTP route when present, else the model's render path. */
function routeTemplate(finding: Finding, plan: ReflectedPlan): string {
  const fromFinding = finding.httpRoute?.replace(/^\S+\s+/, "");
  return fromFinding ?? plan.render.path;
}

async function proveReflected(finding: Finding, plan: ReflectedPlan, payload: string, marker: string, target: Target, deps: XssProofDeps): Promise<XssProof> {
  // Build the path from the authoritative route template, filling STRUCTURAL path params with ids the route accepts
  // (not model-invented strings like "shop123"); the payload goes only in the injectable query/path param.
  const template = routeTemplate(finding, plan);
  const buildPath = (value: string) =>
    template.replace(/:([A-Za-z_]\w*)/g, (_m, name: string) => (plan.render.in === "path" && name === plan.render.param ? encodeURIComponent(value) : PATH_PARAM_ID));
  const buildUrl = (value: string) => {
    const base = (plan.render.client ? deps.clientBase : target.base) ?? target.base;
    const path = buildPath(value);
    assertLocalTarget(base + path); // defense in depth
    return plan.render.in === "path" ? base + path : `${base + path}?${plan.render.param}=${encodeURIComponent(value)}`;
  };
  const exploit = await deps.browser.load(buildUrl(payload), plan.render.authenticated);
  const baseline = await deps.browser.load(buildUrl(plan.benign), plan.render.authenticated);
  return decide(exploit, baseline, marker, `Reflected XSS: payload in "${plan.render.param}" was rendered and executed in the browser (${buildPath("…")}).`);
}

async function proveStored(plan: StoredPlan, payload: string, marker: string, target: Target, deps: XssProofDeps): Promise<XssProof> {
  const url = renderUrl(plan.render, target, deps.clientBase);
  const field = plan.write.bodyField; // the field written and restored; the read-back must return this one
  // Read the field through a given route, or undefined when that route does not carry it.
  const readFrom = async (path: string): Promise<string | undefined> => {
    const res = await target.request("GET", path, { authenticated: true });
    if (!ok(res.status)) return undefined;
    const v = findField(parse(res.body), field);
    return typeof v === "string" ? v : v === undefined ? undefined : JSON.stringify(v);
  };
  // Snapshot via a route that actually returns the field, without trusting the model's guess: try its read-back, then
  // routes derived from the write path (its resource, a sibling detail/profile route, the field as its own resource).
  let readPath: string | undefined;
  let original: string | undefined;
  for (const path of readBackCandidates(plan)) {
    const v = await readFrom(path);
    if (v !== undefined) {
      [readPath, original] = [path, v];
      break;
    }
  }
  // Abort-before-write invariant: a resource we cannot snapshot (and therefore cannot restore) is never mutated.
  if (original === undefined || readPath === undefined) {
    return {
      kind: "unverified",
      reason: `could not snapshot the target field "${field}" via any read-back route (tried ${readBackCandidates(plan).join(", ")}), so no payload was written (left the fixture unchanged).`,
    };
  }

  const read = () => readFrom(readPath!);
  const write = (value: string) => target.request(plan.write.method, plan.write.path, { body: { [field]: value }, authenticated: true });
  let exploit: LoadResult, baseline: LoadResult, restored = false;
  try {
    const w1 = await write(payload);
    if (!ok(w1.status)) return { kind: "unverified", reason: `could not store the payload (write returned ${w1.status} on ${plan.write.method} ${plan.write.path})` };
    exploit = await deps.browser.load(url, plan.render.authenticated);
    await write(plan.benign);
    baseline = await deps.browser.load(url, plan.render.authenticated);
  } finally {
    const back = await write(original);
    restored = ok(back.status) && (await read()) === original;
  }
  const restoreNote = restored ? " The original value was restored." : " RE-SEED RECOMMENDED: the original value could not be restored.";
  return decide(
    exploit,
    baseline,
    marker,
    `Stored XSS: payload written via ${plan.write.method} ${plan.write.path} executed when ${plan.render.path} rendered it.${restoreNote}`,
  );
}

/** Confirmed only when the exploit load reported the exact injected marker and the benign baseline reported none. */
function decide(exploit: LoadResult, baseline: LoadResult, marker: string, confirmSummary: string): XssProof {
  const exEv = loadEvidence(exploit, exploit.marker ? `payload executed (marker ${exploit.marker} reported)` : "no payload executed (no marker)");
  const baseEv = loadEvidence(baseline, baseline.marker ? `marker ${baseline.marker} unexpectedly reported` : "no marker (benign value did not execute)");
  if (exploit.marker === marker && baseline.marker === null) {
    return { kind: "confirmed", verification: { outcome: "confirmed", summary: confirmSummary, baseline: baseEv, exploit: exEv } };
  }
  const why = exploit.marker === null ? "the payload did not execute in the browser" : baseline.marker !== null ? "the benign baseline also executed, so execution is not attributable to the payload" : "the executed marker did not match the one injected";
  return { kind: "unverified", reason: `execution did not confirm the finding: ${why}.`, verification: { outcome: "unverified", summary: `XSS execution proof: ${why}.`, baseline: baseEv, exploit: exEv } };
}
