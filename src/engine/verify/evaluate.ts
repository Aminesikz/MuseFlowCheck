// The verification oracle: given a Check and the two real HTTP responses, decide success deterministically.
// This is where "confirmed" is earned — the model proposed the check, but the comparison here is what proves it.
import type { Check } from "./poc.js";

export interface RawResponse {
  status: number;
  body: string;
  /** The request that produced it, when known: its path with the query string, and the body it sent. */
  path?: string;
  sent?: string;
}

export interface Evaluation {
  success: boolean;
  /** Human-readable account of the comparison, used as finding evidence. */
  detail: string;
}

const ok = (status: number) => status >= 200 && status < 300;
const rejected = (status: number) => status === 401 || status === 403 || status === 404;

/** Parses a response body as JSON, or undefined when it is not JSON. */
export function parse(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

/** The first array found in a value: the value itself, `value[field]`, or the first array among nested values. */
function findArray(value: unknown, field?: string): unknown[] | undefined {
  if (field !== undefined) {
    const at = findField(value, field);
    return Array.isArray(at) ? at : undefined;
  }
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") {
    for (const v of Object.values(value)) if (Array.isArray(v)) return v;
  }
  return undefined;
}

/** First occurrence of `field` anywhere in a JSON value (breadth-first), or undefined. */
export function findField(value: unknown, field: string): unknown {
  const queue: unknown[] = [value];
  while (queue.length > 0) {
    const v = queue.shift();
    if (!v || typeof v !== "object") continue;
    if (!Array.isArray(v) && field in (v as object)) return (v as Record<string, unknown>)[field];
    queue.push(...Object.values(v));
  }
  return undefined;
}

/** JSON with object keys sorted (recursively), so bodies that differ only in key order compare equal. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v) =>
    v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : v,
  );
}

/** Text as a reader sees it: HTML entities and URL percent-escapes decoded and `+` read as a space, so an echo of a request matches it in whichever of those encodings it comes back. */
function decoded(text: string): string {
  const entities: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
  return text
    .replace(/\+/g, " ")
    .replace(/(?:%[0-9a-f]{2})+/gi, (seq) => {
      try {
        return decodeURIComponent(seq);
      } catch {
        return seq;
      }
    })
    .replace(/&(?:#(\d+)|#x([0-9a-f]+)|(\w+));/gi, (m, dec, hex, name) =>
      dec ? String.fromCodePoint(Number(dec)) : hex ? String.fromCodePoint(parseInt(hex, 16)) : (entities[name.toLowerCase()] ?? m),
    );
}

/** Characters of context either side of a marker that, when also found in the request, show the marker was echoed. */
const ECHO_CONTEXT = 6;

/**
 * Occurrences of a marker in a response that are not just the request echoed back — an error page or a search page
 * repeating the URL or body. An echo carries the injected text around the marker, so the marker together with a few
 * characters on either side also appears in the request; a value the database returned sits in the response's own
 * markup instead. Conservative: an occurrence that might be an echo is not counted.
 */
function returnedMarkers(marker: string, response: RawResponse): { total: number; returned: number } {
  const body = decoded(response.body);
  const request = decoded(`${response.path ?? ""}\n${response.sent ?? ""}`);
  let total = 0;
  let returned = 0;
  for (let i = body.indexOf(marker); i !== -1; i = body.indexOf(marker, i + 1)) {
    total++;
    const before = body.slice(Math.max(0, i - ECHO_CONTEXT), i);
    const after = body.slice(i + marker.length, i + marker.length + ECHO_CONTEXT);
    const echoed = (before.length >= 3 && request.includes(before + marker)) || (after.length >= 3 && request.includes(marker + after));
    if (!echoed) returned++;
  }
  return { total, returned };
}

function excerpt(body: string, max = 120): string {
  const clean = body.replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/**
 * Whether a patched copy answered a request exactly as the original did: same status and same body (JSON compared
 * ignoring key order, anything else as trimmed text). Used by patch proof to show a patch kept the route's behavior.
 */
export function sameResponse(original: RawResponse, patched: RawResponse): Evaluation {
  if (original.status !== patched.status) {
    return { success: false, detail: `status ${patched.status}, originally ${original.status}` };
  }
  const a = parse(original.body);
  const b = parse(patched.body);
  const same = a !== undefined && b !== undefined ? canonical(a) === canonical(b) : original.body.trim() === patched.body.trim();
  if (same) return { success: true, detail: `same status (${patched.status}) and same body as before the patch` };
  const ra = findArray(a);
  const rb = findArray(b);
  const rows = ra && rb && ra.length !== rb.length ? ` — ${rb.length} row(s), originally ${ra.length}` : "";
  return {
    success: false,
    detail: `same status (${patched.status}) but a different body${rows} (originally ${JSON.stringify(excerpt(original.body))}, now ${JSON.stringify(excerpt(patched.body))})`,
  };
}

/** True when a response carries no data: an empty body, `[]`, `{}`, or an object whose values are all empty arrays or null. */
export function emptyResult(response: RawResponse): boolean {
  const v = parse(response.body);
  if (v === undefined) return response.body.trim() === "";
  if (Array.isArray(v)) return v.length === 0;
  if (v && typeof v === "object") return Object.values(v).every((x) => x === null || (Array.isArray(x) && x.length === 0));
  return false;
}

/** Evaluates a check against the baseline and exploit responses. Never throws. */
export function evaluate(check: Check, baseline: RawResponse, exploit: RawResponse): Evaluation {
  switch (check.type) {
    case "marker": {
      const marker = JSON.stringify(check.value);
      // A baseline that did not answer normally (a missing route, an error) leaves nothing to compare the exploit with.
      if (!ok(baseline.status)) {
        return { success: false, detail: `the baseline request returned status ${baseline.status}, so the route did not answer normally on this target — there is nothing to compare the exploit with` };
      }
      if (decoded(baseline.body).includes(check.value)) return { success: false, detail: `marker ${marker} appeared in both responses` };
      const { total, returned } = returnedMarkers(check.value, exploit);
      if (total === 0) return { success: false, detail: `marker ${marker} did not appear in the exploit response` };
      if (returned === 0) {
        return { success: false, detail: `marker ${marker} appeared in the exploit response only as an echo of the request (status ${exploit.status}), not as data the query returned` };
      }
      return { success: true, detail: `injected marker ${marker} appeared in the exploit response and not in the baseline` };
    }
    case "more-rows": {
      const b = findArray(parse(baseline.body), check.field);
      const e = findArray(parse(exploit.body), check.field);
      if (!b || !e) return { success: false, detail: `could not find a JSON array to count in both responses (baseline ${b ? b.length : "none"}, exploit ${e ? e.length : "none"})` };
      return {
        success: e.length > b.length,
        detail: `baseline returned ${b.length} row(s); exploit returned ${e.length}${e.length > b.length ? " — the exploit bypassed the filter" : ""}`,
      };
    }
    case "field-differs": {
      const b = findField(parse(baseline.body), check.field);
      const e = findField(parse(exploit.body), check.field);
      const differ = e !== undefined && b !== undefined && JSON.stringify(e) !== JSON.stringify(b);
      return {
        success: ok(exploit.status) && differ,
        detail: differ && ok(exploit.status)
          ? `exploit returned ${check.field}=${JSON.stringify(e)} (status ${exploit.status}) vs the baseline's ${JSON.stringify(b)} — a record from another scope`
          : `${check.field}: baseline=${JSON.stringify(b)}, exploit=${JSON.stringify(e)} (exploit status ${exploit.status})`,
      };
    }
    case "status-unblocked": {
      const success = rejected(baseline.status) && ok(exploit.status) && exploit.body.trim() !== "";
      return {
        success,
        detail: `baseline status ${baseline.status}, exploit status ${exploit.status}${success ? " with a non-empty body — access was not blocked" : ""}`,
      };
    }
  }
}
