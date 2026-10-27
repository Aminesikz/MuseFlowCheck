// Access-control analysis: Stage 1 assembles per-route evidence; Stage 2 has the model judge each candidate route.
import type { Finding } from "../../types/index.js";
import { assembleAccessContext, type AccessContext, type AccessRoute } from "./context.js";
import { judgeRoute, routeLabel } from "./judge.js";

export { assembleAccessContext, type AccessContext, type AccessRoute, type Guard, type Access } from "./context.js";
export { buildAccessPrompt, routeKind, routeLabel, scopingEvidence, secureSiblings } from "./judge.js";

export interface AccessJudgeResult {
  findings: Finding[];
  failures: { route: string; error: unknown }[];
  /** Candidate routes the model judged not vulnerable. */
  cleared: AccessRoute[];
  calls: number;
}

/** Model calls in flight at once. */
const CONCURRENCY = 3;

/** Candidate routes to judge, optionally narrowed to routes whose `METHOD /path` contains `filter`. */
export function candidates(ctx: AccessContext, filter?: string): AccessRoute[] {
  return ctx.routes.filter((r) => r.status === "candidate" && (!filter || routeLabel(r).includes(filter)));
}

/** Stage 2: one model call per candidate route. */
export async function judgeAccess(ctx: AccessContext, filter?: string): Promise<AccessJudgeResult> {
  const routes = candidates(ctx, filter);
  const results: ({ finding: Finding | null } | { error: unknown })[] = new Array(routes.length);
  let next = 0;
  const worker = async () => {
    while (next < routes.length) {
      const i = next++;
      try {
        results[i] = { finding: await judgeRoute(ctx, routes[i]) };
      } catch (error) {
        results[i] = { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, routes.length) }, worker));

  const out: AccessJudgeResult = { findings: [], failures: [], cleared: [], calls: routes.length };
  results.forEach((r, i) => {
    if ("error" in r) out.failures.push({ route: routeLabel(routes[i]), error: r.error });
    else if (r.finding) out.findings.push(r.finding);
    else out.cleared.push(routes[i]);
  });
  return out;
}

/** Both stages over a project directory. */
export async function analyzeAccess(dir: string, filter?: string): Promise<{ ctx: AccessContext; result: AccessJudgeResult }> {
  const ctx = assembleAccessContext(dir);
  return { ctx, result: await judgeAccess(ctx, filter) };
}
