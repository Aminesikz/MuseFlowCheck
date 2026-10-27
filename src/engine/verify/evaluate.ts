// The verification oracle: given a Check and the two real HTTP responses, decide success deterministically.
// This is where "confirmed" is earned — the model proposed the check, but the comparison here is what proves it.
import type { Check } from "./poc.js";

export interface RawResponse {
  status: number;
  body: string;
}

export interface Evaluation {
  success: boolean;
  /** Human-readable account of the comparison, used as finding evidence. */
  detail: string;
}

const ok = (status: number) => status >= 200 && status < 300;
const rejected = (status: number) => status === 401 || status === 403 || status === 404;

function parse(body: string): unknown {
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
function findField(value: unknown, field: string): unknown {
  const queue: unknown[] = [value];
  while (queue.length > 0) {
    const v = queue.shift();
    if (!v || typeof v !== "object") continue;
    if (!Array.isArray(v) && field in (v as object)) return (v as Record<string, unknown>)[field];
    queue.push(...Object.values(v));
  }
  return undefined;
}

/** Evaluates a check against the baseline and exploit responses. Never throws. */
export function evaluate(check: Check, baseline: RawResponse, exploit: RawResponse): Evaluation {
  switch (check.type) {
    case "marker": {
      const inExploit = exploit.body.includes(check.value);
      const inBaseline = baseline.body.includes(check.value);
      return {
        success: inExploit && !inBaseline,
        detail: inExploit && !inBaseline
          ? `injected marker ${JSON.stringify(check.value)} appeared in the exploit response and not in the baseline`
          : `marker ${JSON.stringify(check.value)} ${inExploit ? "appeared in both responses" : "did not appear in the exploit response"}`,
      };
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
