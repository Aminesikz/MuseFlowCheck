// Cross-scope id discovery for ":id"-style IDOR verification.
//
// When the model's PoC guesses a victim id that happens to belong to the caller's own scope, the exploit and the
// baseline look identical and the oracle (rightly) refuses to confirm — even though the finding is real. This finds a
// genuinely foreign-owned id the way an attacker would: by requesting the ":id" endpoint across a small, BOUNDED range
// as the authenticated caller and reading the owner/scope field off each response. It never reads the seed script, the
// database, or any fixture internals, and it only ever talks to the configured local Target.
import { findField, parse } from "./evaluate.js";
import type { Target, TargetResponse } from "./target.js";

export interface RouteParam {
  method: string;
  /** The path with its parameter, e.g. "/api/orders/:id". */
  template: string;
  /** The varied parameter's name, e.g. "id". */
  param: string;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);
export const isMutating = (method: string): boolean => MUTATING.has(method.toUpperCase());

/** Parses "METHOD /a/:id/b" into its method, path template and the (last) path parameter, or undefined if none. */
export function routeParam(httpRoute: string | undefined): RouteParam | undefined {
  if (!httpRoute) return undefined;
  const sp = httpRoute.indexOf(" ");
  if (sp < 0) return undefined;
  const method = httpRoute.slice(0, sp).toUpperCase();
  const template = httpRoute.slice(sp + 1).trim();
  const matches = [...template.matchAll(/:([A-Za-z_]\w*)/g)];
  if (matches.length === 0) return undefined;
  return { method, template, param: matches[matches.length - 1][1] };
}

/** Substitutes the route's LAST path parameter with `id` (earlier params, if any, are left as-is). */
export function fillParam(rp: RouteParam, id: string | number): string {
  const matches = [...rp.template.matchAll(/:([A-Za-z_]\w*)/g)];
  const last = matches[matches.length - 1];
  if (!last) return rp.template;
  const start = last.index ?? 0;
  const token = last[0];
  return rp.template.slice(0, start) + String(id) + rp.template.slice(start + token.length);
}

const ok = (status: number): boolean => status >= 200 && status < 300;

export interface Discovered {
  id: number;
  owner: unknown;
  response: TargetResponse;
}

/**
 * Probes `GET <template>` for ids 1..range as the caller and returns the first id whose `ownerField` on a successful
 * response differs from the caller's own value (`ownScope`). Returns undefined if none is found within the range.
 * Bounded by `range` by construction: it cannot enumerate beyond it.
 */
export async function discoverCrossScopeId(
  target: Target,
  rp: RouteParam,
  ownerField: string,
  ownScope: unknown,
  range: number,
): Promise<Discovered | undefined> {
  const own = JSON.stringify(ownScope);
  for (let id = 1; id <= range; id++) {
    let res: TargetResponse;
    try {
      res = await target.request("GET", fillParam(rp, id), {});
    } catch {
      continue; // a request that cannot be sent is not a discovery; keep probing within the bound
    }
    if (!ok(res.status)) continue;
    const owner = findField(parse(res.body), ownerField);
    if (owner !== undefined && JSON.stringify(owner) !== own) return { id, owner, response: res };
  }
  return undefined;
}
