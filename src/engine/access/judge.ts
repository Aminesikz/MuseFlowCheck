// Stage 2 of access-control analysis: the model judges each candidate route from the assembled evidence.
// Locations, taintPath, type and CWE come from Stage 1; the model only decides and explains.
// Keep this prompt codebase-agnostic: describe ownership and checks by behavior, never by any test app's names.
import { complete } from "../../llm/meta-client.js";
import type { Finding, Severity } from "../../types/index.js";
import { codeSlice, formatHop } from "../crossfile/judge.js";
import type { FunctionRef } from "../crossfile/trace.js";
import { extractJsonArray, FindingParseError, validateJudgment } from "../parse.js";
import { ownerColumns, scopeTables, type Access, type AccessContext, type AccessKind, type AccessRoute } from "./context.js";

/** Type and CWE follow from what the route does with the record: a read is IDOR, a write is missing authorization. */
export const ACCESS_CLASSES: Record<AccessKind, { type: string; cwe: string }> = {
  read: { type: "IDOR", cwe: "CWE-639" },
  write: { type: "Broken Access Control", cwe: "CWE-862" },
};

/**
 * Whether an unchecked access reaches past the caller's own scope, as Stage 1 establishes it from the schema:
 * "cross-scope" when the rows it reads or changes belong to an owner (cross-tenant / cross-user data), "unestablished"
 * when the code does not show that they do.
 */
export type AccessReach = "cross-scope" | "unestablished";

/**
 * The route's reach, read from the schema and the route's unchecked accesses — never from the model. "cross-scope"
 * when a request value selects rows of a table the schema ties to an owner (an ownership column), or of a table that
 * is itself a scope record, with no check on the path; otherwise "unestablished" (no schema, or ownership only
 * inferred from a statement). Taken over all the route's unchecked accesses, so the path the judge cites cannot move it.
 */
export function accessReach(ctx: AccessContext, route: AccessRoute): { level: AccessReach; evidence?: string } {
  const owners = ownerColumns(route.identity);
  const scopes = scopeTables(ctx.schema, owners);
  for (const a of route.accesses) {
    const verb = a.kind === "write" ? "changes" : "reads";
    for (const table of a.tables) {
      const schema = ctx.schema.find((t) => t.name === table);
      const owner = schema?.columns.find((c) => owners.has(c.name));
      if (owner) {
        return { level: "cross-scope", evidence: `${table}.${owner.name} (${schema!.file}:${owner.line}) ties each ${table} row to an owner, and the request value ${a.location}.${a.field} ${verb} ${table} rows with no check against the caller's own ${route.identity!.expression}.${owners.get(owner.name)}` };
      }
      const scope = scopes.get(table);
      if (scope) {
        return { level: "cross-scope", evidence: `${table} is itself a scope record (identified by ${route.identity!.expression}.${scope.field}), and the request value ${a.location}.${a.field} ${verb} ${table} rows with no check against the caller's own` };
      }
    }
  }
  return { level: "unestablished" };
}

/** The ordered access-control severity rule: an unchecked read or write across an ownership boundary is critical; otherwise high. */
export function accessSeverity(ctx: AccessContext, route: AccessRoute): Severity {
  return accessReach(ctx, route).level === "cross-scope" ? "critical" : "high";
}

/** The access-control severity rule, stated with this route's reach and resulting level — applied, not re-derived. */
function severityRule(ctx: AccessContext, route: AccessRoute): string {
  const { level, evidence } = accessReach(ctx, route);
  const reach =
    level === "cross-scope"
      ? `crosses an ownership boundary — ${evidence}: the caller reaches other users' or tenants' records.`
      : "not established — the schema does not show that the accessed rows belong to an owner, so reaching beyond the caller's own scope is not shown by the code.";
  return `ACTOR REACH (from Stage 1, read from the schema and the route's unchecked accesses): ${reach}

SEVERITY — access-control rule. Check these IN ORDER and assign the FIRST one that matches, using the ACTOR REACH above:
1. "critical" — the unchecked access crosses an ownership boundary (reach: crosses an ownership boundary): the caller reads or modifies another user's or tenant's records — their personal data, financial data, or any record they own — or changes or deletes them.
2. "high" — reaching beyond the caller's own scope is not established by the code (reach: not established), so the exposure is limited to the caller's own scope or is lower-impact.
3. "medium" or "low" — only for a specific reason visible in the code that limits the impact (e.g. only non-sensitive fields are exposed, or a strong precondition), stated in the explanation.
The level follows from this rule and the reach above — do not re-derive impact. For this route the rule gives "${accessSeverity(ctx, route)}". State the reach in the explanation.`;
}

export function routeLabel(r: AccessRoute): string {
  return `${r.method} ${r.path}`;
}

export function routeKind(r: AccessRoute): AccessKind {
  return r.accesses.some((a) => a.kind === "write") ? "write" : "read";
}

/** Evidence from the schema and statements about whether the accessed rows belong to someone. */
export function scopingEvidence(ctx: AccessContext, route: AccessRoute): string[] {
  const owners = ownerColumns(route.identity);
  const scopes = scopeTables(ctx.schema, owners);
  const lines: string[] = [];

  const seen = new Set<string>();
  for (const a of route.accesses) {
    for (const table of a.tables) {
      if (seen.has(`${table}:${a.column}`)) continue;
      seen.add(`${table}:${a.column}`);
      const schema = ctx.schema.find((t) => t.name === table);
      const owner = schema?.columns.find((c) => owners.has(c.name));
      const scope = scopes.get(table);
      if (owner) {
        const ref = owner.references ? `, REFERENCES ${owner.references.table}(${owner.references.column})` : "";
        lines.push(`${table}.${owner.name} (${schema!.file}:${owner.line}${ref}) ties each ${table} row to an owner — the caller's own value is ${route.identity!.expression}.${owners.get(owner.name)}.`);
      } else if (scope) {
        lines.push(`${table} is itself the scope record: ${route.identity!.expression}.${scope.field} identifies a ${table} row, and ${scope.referencedBy.join(", ")} reference it.`);
      } else if (!schema && [...owners.keys()].some((c) => new RegExp(`\\b${c}\\b`, "i").test(a.sql))) {
        lines.push(`No schema found for ${table}, but its statements reference an owner column (${[...owners.keys()].filter((c) => new RegExp(`\\b${c}\\b`, "i").test(a.sql)).join(", ")}).`);
      } else {
        lines.push(`No ownership column for ${table} was found in the schema or its statements.`);
      }
      if (!a.column) continue;
      if (owner && a.column === owner.name) {
        lines.push(`The request value ${a.location}.${a.field} is used as ${table}.${a.column} — it chooses whose ${table} rows are ${a.kind === "write" ? "changed" : "read"}.`);
      } else if (scope && a.column === "id") {
        lines.push(`The request value ${a.location}.${a.field} chooses which ${table} row (scope record) is ${a.kind === "write" ? "changed" : "read"}.`);
      } else if (owner) {
        lines.push(`The request value ${a.location}.${a.field} selects one ${table} row by ${a.column}; the statement does not filter on ${owner.name}.`);
      }
    }
  }
  return lines;
}

/** Guarded routes that best show the intended policy for this one: same table, same path parameter, same area. */
export function secureSiblings(ctx: AccessContext, route: AccessRoute, max = 3): AccessRoute[] {
  const tables = new Set(route.accesses.flatMap((a) => a.tables));
  const params = new Set(route.path.match(/:\w+/g) ?? []);
  const area = route.path.split("/").slice(0, 3).join("/");
  return ctx.routes
    .filter((r) => r !== route && r.status === "guarded")
    .map((r) => {
      let score = 0;
      if (r.tables.some((t) => tables.has(t))) score += 3;
      if ((r.path.match(/:\w+/g) ?? []).some((p) => params.has(p))) score += 3;
      if (r.path.startsWith(area)) score += 1;
      if (r.guards.some((g) => g.kind !== "query constrained by identity")) score += 1; // an explicit comparison is clearer evidence
      return { r, score };
    })
    .filter(({ score }) => score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, max)
    .map(({ r }) => r);
}

function siblingLine(r: AccessRoute): string {
  const checks = r.guards.map((g) => `${g.kind} at ${g.file}:${g.line}: ${g.code}`).join("; ");
  const data = r.tables.length > 0 ? ` (data: ${r.tables.join(", ")})` : "";
  return `- ${routeLabel(r)}${data} — ${checks}`;
}

function accessBlock(a: Access, n: number): string {
  const hops = a.path.hops.map((h, i) => `  ${i + 1}. [${h.kind}] ${formatHop(h)}`).join("\n");
  const target = a.column ? `${a.tables.join(", ")}.${a.column}` : a.tables.join(", ");
  return `Path ${n}: [${a.kind}] ${a.location}.${a.field} → ${target}\n${hops}\n  statement: ${a.sql}`;
}

/** Every distinct function whose code the judge should read for this route. */
function codeFor(ctx: AccessContext, route: AccessRoute, siblings: AccessRoute[]): FunctionRef[] {
  const refs = new Map<string, FunctionRef>();
  const add = (ref: FunctionRef | undefined) => ref && refs.set(`${ref.file}:${ref.startLine}`, ref);
  route.functions.forEach(add);
  add(route.identity?.middleware);
  for (const s of siblings) s.guards.forEach((g) => add(g.fn));
  return [...refs.values()];
}

export function buildAccessPrompt(ctx: AccessContext, route: AccessRoute): string {
  const kind = routeKind(route);
  const { type, cwe } = ACCESS_CLASSES[kind];
  const siblings = secureSiblings(ctx, route);
  const identity = route.identity!;
  const ownChecks = route.guards.length > 0 ? route.guards.map((g) => `- ${g.kind} at ${g.file}:${g.line}: ${g.code} (does not cover the paths above)`).join("\n") : "- none found";

  return `You are a senior security code reviewer. Decide whether ONE HTTP route has a broken access control / insecure direct object reference (IDOR) vulnerability: it reads or modifies a record selected by request-supplied input without verifying that the record belongs to the authenticated caller's scope (their own user, tenant, organization, team or account).

A route that takes an identifier is NOT automatically vulnerable. Report a finding ONLY when ALL THREE hold, and cite the evidence for each:
A. IDENTITY AVAILABLE — the route runs after authentication that exposes the caller's scope (a user id, a tenant id, …), so the route could have checked it.
B. RESOURCE IS SCOPED — the data model ties the accessed rows to an owner or tenant (an ownership column or foreign key), or the row IS a scope record (e.g. the tenant itself). Public or shared data — catalogues, reference/lookup tables, anything every authenticated caller may see — is not scoped.
C. NO CHECK ENFORCES THE SCOPE — nowhere on the access path (handler, services, data layer, middleware) is the record's owner, or the requested scope id, compared with the caller's identity, and the statement is not constrained by the caller's identity. Sibling routes that DO enforce such a check show the application's intended policy for scoped data, even for a different record type.
If A, B or C is missing or doubtful, return []. Do not report other vulnerability classes (injection, missing authentication, mass assignment, rate limiting). Do not report a route because it could be stricter — only if a caller can read or change another scope's records.

ROUTE: ${routeLabel(route)} — handler ${route.handler.file}:${route.handler.startLine}, registered at ${route.registeredAt}

ACCESS — request-supplied identifier → data access (traced; interpolated values in statements appear as {{name}}):
${route.accesses.map((a, i) => accessBlock(a, i + 1)).join("\n\n")}

A. IDENTITY
- ${identity.evidence}.
- Fields available on ${identity.expression}: ${identity.fields.join(", ") || "unknown"}.

B. RESOURCE SCOPING (from the schema and the statements)
${scopingEvidence(ctx, route).map((l) => `- ${l}`).join("\n") || "- no schema or ownership information found"}

C. CHECKS
On this route:
${ownChecks}
Secure sibling routes (they enforce a check):
${siblings.map(siblingLine).join("\n") || "- none found"}

CODE — the route's functions, the identity middleware, and the sibling checks, with real file line numbers prefixed as "N | "
${codeFor(ctx, route, siblings).map(codeSlice).join("\n\n")}

${severityRule(ctx, route)}

OUTPUT
Return ONLY a JSON array — no prose, no markdown fences.
- [] if A, B or C does not hold.
- Otherwise exactly ONE object:
{
  "type": "${type}",
  "cwe": "${cwe}",
  "severity": "critical" | "high" | "medium" | "low",
  "path": number,            // the "Path N" number above that most clearly shows the unchecked access
  "explanation": string,     // must cite (A) which identity field was available and not used, (B) how the record is scoped in the data model, (C) which sibling route enforces the check (or that none does) — then what an attacker could do
  "suggestedPatch": string   // corrected code for the handler (or the function that loads the record) adding the scope check, in the same style
}
This route ${kind === "write" ? "modifies" : "reads"} the record, so type is "${type}" and cwe is "${cwe}".
Do not include file, line, or taintPath fields — the tool fills those in from the traced path.`;
}

/**
 * Parses the judge's reply into one Finding (or null when it judged the route not vulnerable). Severity follows the
 * access-control rule: critical/high is the rule's level for this route's reach; only a medium/low downgrade, which
 * the rule reserves for a stated reason in the code, is taken from the model.
 */
export function parseAccessJudgment(raw: string, route: AccessRoute, ctx: AccessContext): Finding | null {
  const items = extractJsonArray(raw);
  if (items.length === 0) return null;
  try {
    const judgment = validateJudgment(items[0], 0);
    const n = Number((items[0] as Record<string, unknown>).path);
    const access = (Number.isInteger(n) && route.accesses[n - 1]) || route.accesses[0];
    const severity = judgment.severity === "critical" || judgment.severity === "high" ? accessSeverity(ctx, route) : judgment.severity;
    const source = access.path.hops[0];
    const sink = access.path.hops.at(-1)!;
    return {
      ...judgment,
      severity,
      ...ACCESS_CLASSES[routeKind(route)],
      file: source.file,
      sourceLine: source.line,
      ...(sink.file !== source.file ? { sinkFile: sink.file } : {}),
      sinkLine: sink.line,
      taintPath: access.path.hops.map(formatHop),
      httpRoute: routeLabel(route), // metadata for the verifier (e.g. "GET /api/x/:id"); not used by analysis
      confidence: "suspected",
    };
  } catch (err) {
    throw new FindingParseError(`judge response does not match the expected schema: ${(err as Error).message}`, raw);
  }
}

export async function judgeRoute(ctx: AccessContext, route: AccessRoute): Promise<Finding | null> {
  return parseAccessJudgment(await complete(buildAccessPrompt(ctx, route)), route, ctx);
}
