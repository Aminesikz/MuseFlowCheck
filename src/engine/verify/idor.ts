// Discovery-based proof for ":id"-style IDOR findings, where the model's guessed victim id may belong to the caller's
// own scope. Both flows discover a genuinely foreign-owned id by bounded probing (see discover.ts) and then prove the
// access against it, keeping the oracle discipline: a finding is confirmed only on an observed cross-scope difference.
//
// Read (CWE-639): request the discovered foreign id as the caller and confirm it returns a record whose owner differs.
// Write (CWE-862): snapshot the foreign resource, apply the mutation to it, read it back to show the change took effect
// cross-scope, then restore it. All requests go only to the configured local Target. The own-scope "baseline" write is
// a no-op (the resource's own current values), so the caller's own data is never actually changed.
import type { Finding, Verification } from "../../types/index.js";
import { findField, parse } from "./evaluate.js";
import { evidence } from "./evidence.js";
import { discoverCrossScopeId, fillParam, isMutating, type RouteParam } from "./discover.js";
import type { Poc } from "./poc.js";
import type { Target, TargetResponse } from "./target.js";

const ok = (status: number): boolean => status >= 200 && status < 300;
const differs = (a: unknown, b: unknown): boolean => a !== undefined && JSON.stringify(a) !== JSON.stringify(b);

/** A finding this discovery proof applies to: a broken-access-control / IDOR report. */
export function isAccessFinding(finding: Finding): boolean {
  return finding.cwe === "CWE-639" || finding.cwe === "CWE-862" || /idor|access control/i.test(finding.type);
}

export type IdorProof = { kind: "confirmed"; verification: Verification } | { kind: "unverified"; reason: string };

interface Req {
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  authenticated?: boolean;
}
const send = (target: Target, req: Req): Promise<TargetResponse> =>
  target.request(req.method, req.path, { query: req.query, body: req.body, authenticated: req.authenticated });

/** Fields the exploit's body sets, as a plain object (empty for a bodyless method such as DELETE). */
function bodyFields(poc: Poc): Record<string, unknown> {
  return poc.exploit.body && typeof poc.exploit.body === "object" ? (poc.exploit.body as Record<string, unknown>) : {};
}

const ID_LIKE = /^id$|_id$|Id$|ID$/;
const isScalar = (v: unknown): v is string | number | boolean => typeof v === "string" || typeof v === "number" || typeof v === "boolean";

/** The first object in a parsed body that carries `ownerField` — i.e. the resource itself (handles `{resource:{…}}`). */
function resourceObject(value: unknown, ownerField: string): Record<string, unknown> | undefined {
  const queue: unknown[] = [value];
  while (queue.length > 0) {
    const v = queue.shift();
    if (!v || typeof v !== "object") continue;
    if (!Array.isArray(v) && ownerField in (v as object)) return v as Record<string, unknown>;
    queue.push(...Object.values(v as object));
  }
  return undefined;
}

/**
 * Ordered single-field writes to try on the foreign resource, each set to a value that DIFFERS from its current one so
 * the write is observable. Drawn only from observed data — the model's exploit body first, then, for each of the
 * foreign resource's scalar fields, the distinct values that same field carries on the resources already probed (and
 * the caller's own) — so the values are real and app-valid (e.g. a status the API accepts). The owner field and
 * id-like fields are never written. Bounded to a handful of candidates.
 */
function writeCandidates(poc: Poc, before: TargetResponse, ownRead: TargetResponse, seen: unknown[], ownerField: string): { field: string; value: unknown }[] {
  const foreign = resourceObject(parse(before.body), ownerField);
  const out: { field: string; value: unknown }[] = [];
  const add = (field: string, value: unknown) => {
    if (!out.some((c) => c.field === field && JSON.stringify(c.value) === JSON.stringify(value))) out.push({ field, value });
  };
  for (const [k, v] of Object.entries(bodyFields(poc))) {
    if (differs(v, findField(foreign ?? parse(before.body), k))) add(k, v);
  }
  if (foreign) {
    const pool = [parse(ownRead.body), ...seen]; // resources whose field values are real and accepted by the app
    for (const [k, current] of Object.entries(foreign)) {
      if (k === ownerField || ID_LIKE.test(k) || !isScalar(current)) continue;
      for (const src of pool) {
        const v = findField(src, k);
        if (isScalar(v) && differs(v, current)) add(k, v);
      }
    }
  }
  return out.slice(0, 24);
}

/**
 * Read IDOR: run as a fallback after the model's own exploit failed to differ. `baseline` is the model's benign
 * own-scope response, already fetched, used to anchor the caller's own scope.
 */
export async function proveReadIdor(
  poc: Poc,
  rp: RouteParam,
  ownerField: string,
  target: Target,
  baseline: TargetResponse,
  range: number,
): Promise<IdorProof> {
  const ownScope = findField(parse(baseline.body), ownerField);
  if (ownScope === undefined) {
    return { kind: "unverified", reason: `could not read the caller's own ${ownerField} from the baseline response to anchor id discovery` };
  }
  const disc = await discoverCrossScopeId(target, { ...rp, method: "GET" }, ownerField, ownScope, range);
  if (!disc) {
    return { kind: "unverified", reason: `no resource owned by another scope was found probing GET ${rp.template} for ids 1..${range}; cannot prove cross-scope access` };
  }
  const exploitRes = await send(target, { method: rp.method, path: fillParam(rp, disc.id), authenticated: poc.exploit.authenticated ?? true });
  const foreign = findField(parse(exploitRes.body), ownerField);
  if (!(ok(exploitRes.status) && differs(foreign, ownScope))) {
    return {
      kind: "unverified",
      reason: `id ${disc.id} (${ownerField}=${JSON.stringify(disc.owner)}) was discovered by probing, but requesting it returned no cross-scope record (status ${exploitRes.status}, ${ownerField}=${JSON.stringify(foreign)})`,
    };
  }
  return {
    kind: "confirmed",
    verification: {
      outcome: "confirmed",
      summary:
        `Probed ${rp.template} as the caller (own ${ownerField}=${JSON.stringify(ownScope)}) and found id ${disc.id} owned by ${ownerField}=${JSON.stringify(foreign)}. ` +
        `Confirmed: requesting it returned that other scope's record without an ownership check. ${poc.rationale}`,
      baseline: evidence(baseline),
      exploit: evidence(exploitRes),
    },
  };
}

/** Whether the mutation took effect on the resource: a changed field matching the exploit body, or a deletion. */
function mutationEffect(before: TargetResponse, after: TargetResponse, body: Record<string, unknown>, method: string): { tookEffect: boolean; detail: string } {
  if (method === "DELETE") {
    const gone = !ok(after.status) || after.body.trim() === "" || parse(after.body) === undefined;
    return { tookEffect: ok(before.status) && gone, detail: gone ? "the resource no longer exists after the request" : "the resource still exists after the request" };
  }
  const b = parse(before.body);
  const a = parse(after.body);
  for (const [k, v] of Object.entries(body)) {
    const av = findField(a, k);
    const bv = findField(b, k);
    if (JSON.stringify(av) === JSON.stringify(v) && JSON.stringify(av) !== JSON.stringify(bv)) {
      return { tookEffect: true, detail: `${k} changed from ${JSON.stringify(bv)} to ${JSON.stringify(av)}` };
    }
  }
  return { tookEffect: false, detail: "no field from the request body changed on the resource" };
}

/** Puts the foreign resource back the way it was, so the fixture is not left mutated. Best-effort; reports the state. */
async function restore(target: Target, path: string, before: TargetResponse, keys: string[], method: string): Promise<string> {
  if (method === "DELETE" || method === "POST") return "RE-SEED RECOMMENDED: the request created or deleted a record and cannot be reverted automatically";
  const original = parse(before.body);
  const revert: Record<string, unknown> = {};
  for (const k of keys) {
    const v = findField(original, k);
    if (v !== undefined) revert[k] = v;
  }
  if (Object.keys(revert).length === 0) return "RE-SEED RECOMMENDED: could not determine the resource's original values to revert the write";
  try {
    await send(target, { method, path, body: revert, authenticated: true });
    const check = await send(target, { method: "GET", path, authenticated: true });
    const now = parse(check.body);
    const reverted = Object.entries(revert).every(([k, v]) => JSON.stringify(findField(now, k)) === JSON.stringify(v));
    return reverted ? "restored: the foreign resource was reverted to its original values" : "RE-SEED RECOMMENDED: reverting the foreign resource did not restore its original values";
  } catch {
    return "RE-SEED RECOMMENDED: the foreign resource could not be reverted";
  }
}

/**
 * Write IDOR: a self-contained proof run before any generic request, so no stray mutation happens. Establishes the
 * caller's own scope with a read, discovers a foreign resource, mutates it, reads it back, then restores it.
 */
export async function proveWriteIdor(poc: Poc, rp: RouteParam, ownerField: string, target: Target, range: number): Promise<IdorProof> {
  const ownRead = await send(target, { method: "GET", path: poc.baseline.path, authenticated: poc.baseline.authenticated ?? true });
  const ownScope = findField(parse(ownRead.body), ownerField);
  if (ownScope === undefined) {
    return { kind: "unverified", reason: `could not read the caller's own ${ownerField} from GET ${poc.baseline.path} to anchor id discovery` };
  }
  const disc = await discoverCrossScopeId(target, { ...rp, method: "GET" }, ownerField, ownScope, range);
  if (!disc) {
    return { kind: "unverified", reason: `no resource owned by another scope was found probing GET ${rp.template} for ids 1..${range}; cannot prove a cross-scope write` };
  }
  const foreignPath = fillParam(rp, disc.id);
  const before = await send(target, { method: "GET", path: foreignPath, authenticated: true });
  // Abort-before-write invariant: never mutate a resource we could not first snapshot, or we cannot restore it.
  if (!ok(before.status) || resourceObject(parse(before.body), ownerField) === undefined) {
    return { kind: "unverified", reason: `could not snapshot foreign resource ${foreignPath} (status ${before.status}) before writing, so no write was performed` };
  }

  // Apply the mutation. For a bodyless method (DELETE) there is one attempt; otherwise try candidate single-field
  // writes one at a time and stop at the first the server actually applies, so only the minimum is changed.
  let mutate: TargetResponse;
  let after: TargetResponse;
  let effect = { tookEffect: false, detail: "no writable field could be derived to change the resource" };
  let changedField: string | undefined;
  if (rp.method === "DELETE") {
    mutate = await send(target, { method: rp.method, path: foreignPath, authenticated: poc.exploit.authenticated ?? true });
    after = await send(target, { method: "GET", path: foreignPath, authenticated: true });
    effect = mutationEffect(before, after, {}, rp.method);
  } else {
    const candidates = writeCandidates(poc, before, ownRead, disc.seen, ownerField);
    // Fall back to the model's own body so there is always at least one attempt (and a response to report).
    const attempts = candidates.length > 0 ? candidates.map((c) => ({ [c.field]: c.value })) : [bodyFields(poc)];
    mutate = await send(target, { method: rp.method, path: foreignPath, body: attempts[0], authenticated: poc.exploit.authenticated ?? true });
    after = await send(target, { method: "GET", path: foreignPath, authenticated: true });
    for (let i = 0; i < attempts.length; i++) {
      if (i > 0) {
        mutate = await send(target, { method: rp.method, path: foreignPath, body: attempts[i], authenticated: poc.exploit.authenticated ?? true });
        after = await send(target, { method: "GET", path: foreignPath, authenticated: true });
      }
      const e = mutationEffect(before, after, attempts[i], rp.method);
      effect = e;
      if (e.tookEffect) {
        changedField = Object.keys(attempts[i])[0];
        break;
      }
    }
  }
  const afterOwner = findField(parse(after.body), ownerField);

  const confirmed = ok(mutate.status) && differs(afterOwner, ownScope) && effect.tookEffect;
  const state = confirmed ? await restore(target, foreignPath, before, changedField ? [changedField] : [], rp.method) : "no cross-scope write was confirmed, so nothing was changed to restore";

  // Best-effort demonstration that the caller may mutate its OWN resource: a no-op write of the changed field's own value.
  let ownNote = "the caller can read its own resource";
  if (confirmed && changedField !== undefined) {
    const ownVal = findField(parse(ownRead.body), changedField);
    if (ownVal !== undefined) {
      try {
        const ownWrite = await send(target, { method: rp.method, path: poc.baseline.path, body: { [changedField]: ownVal }, authenticated: true });
        ownNote = ok(ownWrite.status) ? "the caller may mutate its own resource (a same-value write succeeded)" : `the caller's own write returned status ${ownWrite.status}`;
      } catch {
        ownNote = "the caller's own write could not be demonstrated";
      }
    }
  }

  if (!confirmed) {
    return {
      kind: "unverified",
      reason:
        `discovered id ${disc.id} (${ownerField}=${JSON.stringify(disc.owner)}), but the cross-scope write was not confirmed: ` +
        `${rp.method} status ${mutate.status}, read-back ${ownerField}=${JSON.stringify(afterOwner)} (own ${JSON.stringify(ownScope)}), ${effect.detail}`,
    };
  }
  return {
    kind: "confirmed",
    verification: {
      outcome: "confirmed",
      summary:
        `Probed ${rp.template} as the caller (own ${ownerField}=${JSON.stringify(ownScope)}) and found id ${disc.id} owned by ${ownerField}=${JSON.stringify(disc.owner)}. ` +
        `Confirmed: ${rp.method} on it succeeded (status ${mutate.status}) and ${effect.detail}, a cross-scope write; ${ownNote}. Fixture state: ${state}.`,
      baseline: evidence(ownRead),
      exploit: evidence(mutate),
    },
  };
}
