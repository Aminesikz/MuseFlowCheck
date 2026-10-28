// PoC generation for verification: the model proposes two requests (a benign baseline and an exploit) plus a
// mechanically checkable success condition. The tool — not the model — evaluates that condition against the real
// responses (see evaluate.ts), so a "confirmed" always rests on an observed difference, never on the model's say-so.
import type { Finding } from "../../types/index.js";
import { extractJsonArray, FindingParseError } from "../parse.js";

export interface PocRequest {
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  /** Send the configured auth token (default true); false for a deliberately unauthenticated request. */
  authenticated?: boolean;
}

/**
 * A success condition the tool can check by comparing the two responses — never the model's own verdict:
 * - marker:          a sentinel the exploit injects (e.g. via UNION) appears in the exploit body but not the baseline's.
 * - more-rows:       the exploit returns strictly more JSON array elements than the baseline (filter bypass / dump).
 * - field-differs:   both responses succeed but carry a different owner/scope value in `field` (cross-tenant access).
 * - status-unblocked: the baseline is rejected (401/403/404) while the exploit succeeds (2xx) with a non-empty body.
 */
export type Check =
  | { type: "marker"; value: string }
  | { type: "more-rows"; field?: string }
  | { type: "field-differs"; field: string }
  | { type: "status-unblocked" };

export interface Poc {
  baseline: PocRequest;
  exploit: PocRequest;
  check: Check;
  rationale: string;
}

const CHECK_GUIDE = `"check" — how the tool will DECIDE success by comparing the two real responses (pick the one your exploit proves):
- {"type":"marker","value":"<sentinel>"}: your exploit injects <sentinel> (e.g. a UNION SELECT of a constant). Confirmed when <sentinel> appears in the exploit response but not the baseline's.
- {"type":"more-rows","field":"<optional json field holding the array>"}: confirmed when the exploit returns strictly more array items than the baseline (e.g. a WHERE bypass dumps rows the baseline does not). Make the baseline a request that legitimately returns few or zero rows.
- {"type":"field-differs","field":"<field name>"}: both requests succeed, but the exploit's response carries a different owner/scope value in <field> than the baseline's (reading another scope's record). Use for direct-object-reference reads/writes.
- {"type":"status-unblocked"}: the baseline is rejected (401/403/404) and the exploit succeeds (2xx) with a body.`;

function requestShape(role: string): string {
  return `  "${role}": {"method":"GET|POST|PUT|PATCH|DELETE","path":"/api/...","query":{"k":"v"},"body":{},"authenticated":true}`;
}

/** The PoC-generation prompt for one finding. `identityHint` describes the token's own scope, when known. */
export function buildPocPrompt(finding: Finding, identityHint?: string): string {
  const isSqli = /sql/i.test(finding.type) || finding.cwe === "CWE-89";
  const goal = isSqli
    ? "Craft an input that makes the query return data a benign request does not — e.g. a boolean/UNION injection that bypasses a filter or echoes an injected marker."
    : "Request a record that belongs to a DIFFERENT scope than the caller's, to show the route returns it without an ownership check.";

  const routeLine = finding.httpRoute ? `\n- HTTP route (the vulnerable endpoint — use this exact method and path): ${finding.httpRoute}` : "";
  const routeRule = finding.httpRoute
    ? `Both requests go to \`${finding.httpRoute}\` — use that exact method and path; do not invent a different URL.`
    : "Both requests go to the same route.";

  return `You are a penetration tester proving one finding against a running LOCAL test instance of the application under review. You have a legitimate low-privilege auth token for one tenant; ${identityHint ?? "its scope is not stated"}.

Produce a proof-of-concept: a benign BASELINE request and an EXPLOIT request to the same endpoint, and a success condition the tool will check by comparing the two responses. ${goal}

FINDING
- ${finding.type} (${finding.cwe}) — ${finding.severity}
- source ${finding.file}:${finding.sourceLine}; sink ${finding.sinkFile ?? finding.file}:${finding.sinkLine}${routeLine}
- request path to the vulnerable code (first hop is the HTTP entry point):
${finding.taintPath.map((h) => `    ${h}`).join("\n")}
- why it is thought exploitable: ${finding.explanation}

${CHECK_GUIDE}

Rules:
- ${routeRule} The baseline is an ordinary, benign request; the exploit differs only by the attack input.
- Put the attack payload in the query or body field the finding's source reads (${finding.taintPath[0] ?? "the entry hop"}).
- Use the provided auth token (authenticated:true) unless proving an unauthenticated-access issue.
- Do NOT request destructive operations beyond what the finding itself describes.

OUTPUT
Return ONLY a JSON array with exactly one object — no prose, no markdown fences:
[{
${requestShape("baseline")},
${requestShape("exploit")},
  "check": { ... one of the forms above ... },
  "rationale": "one sentence: what the exploit does and why the check proves it"
}]`;
}

function toRequest(value: unknown, role: string): PocRequest {
  const r = value as Record<string, unknown>;
  if (!r || typeof r.method !== "string" || typeof r.path !== "string") {
    throw new Error(`${role} must have a string method and path`);
  }
  if (!r.path.startsWith("/")) throw new Error(`${role}.path must start with "/", got ${JSON.stringify(r.path)}`);
  const query = r.query && typeof r.query === "object" ? Object.fromEntries(Object.entries(r.query as object).map(([k, v]) => [k, String(v)])) : undefined;
  return { method: r.method.toUpperCase(), path: r.path, query, body: r.body, authenticated: r.authenticated !== false };
}

function toCheck(value: unknown): Check {
  const c = value as Record<string, unknown>;
  switch (c?.type) {
    case "marker":
      if (typeof c.value !== "string" || c.value === "") throw new Error("check.marker needs a non-empty string value");
      return { type: "marker", value: c.value };
    case "more-rows":
      return { type: "more-rows", ...(typeof c.field === "string" ? { field: c.field } : {}) };
    case "field-differs":
      if (typeof c.field !== "string" || c.field === "") throw new Error("check.field-differs needs a field name");
      return { type: "field-differs", field: c.field };
    case "status-unblocked":
      return { type: "status-unblocked" };
    default:
      throw new Error(`unknown check type ${JSON.stringify(c?.type)}`);
  }
}

/** Parses the model's reply into a PoC, or throws FindingParseError. */
export function parsePoc(raw: string): Poc {
  const items = extractJsonArray(raw);
  if (items.length === 0) throw new FindingParseError("PoC response was an empty array", raw);
  try {
    const o = items[0] as Record<string, unknown>;
    return {
      baseline: toRequest(o.baseline, "baseline"),
      exploit: toRequest(o.exploit, "exploit"),
      check: toCheck(o.check),
      rationale: typeof o.rationale === "string" ? o.rationale : "",
    };
  } catch (err) {
    throw new FindingParseError(`PoC does not match the expected schema: ${(err as Error).message}`, raw);
  }
}
