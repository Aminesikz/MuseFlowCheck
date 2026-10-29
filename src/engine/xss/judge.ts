// Stage 2 of XSS analysis: the model judges whether request input reaching an HTML output is exploitable XSS.
// Locations and taintPath come from the deterministic tracer; the model only decides and explains, and the heart of
// that decision is whether the value is HTML-encoded or sanitized on the way to this particular output.
import { complete } from "../../llm/meta-client.js";
import type { Finding } from "../../types/index.js";
import { codeSlice, formatHop, MAX_PATHS_PER_SINK } from "../crossfile/judge.js";
import type { FunctionRef, Hop } from "../crossfile/trace.js";
import { extractJsonArray, FindingParseError, validateJudgment } from "../parse.js";
import type { Severity } from "../../types/index.js";
import type { Reach, XssPath } from "./trace.js";

export const XSS_TYPE = "Cross-Site Scripting (Reflected)";
export const XSS_STORED_TYPE = "Cross-Site Scripting (Stored)";
export const XSS_CWE = "CWE-79";
/** Encoded outputs of the same input shown for contrast; the rest are counted. */
const MAX_CONTRAST = 5;

/** Raw paths into the same HTML output, plus encoded outputs of the same input elsewhere (context, not under review). */
export interface XssSinkGroup {
  sink: Hop;
  paths: XssPath[];
  omitted: number;
  contrast: XssPath[];
  /** Stored XSS: the `table.column` the input is persisted to (every path of the group goes through it). */
  stored?: string;
}

export function xssType(group: XssSinkGroup): string {
  return group.stored ? XSS_STORED_TYPE : XSS_TYPE;
}

export function groupXssBySink(paths: XssPath[]): XssSinkGroup[] {
  const groups = new Map<string, XssSinkGroup>();
  for (const p of paths.filter((c) => !c.encoded)) {
    const sink = p.hops.at(-1)!;
    const key = `${sink.file}:${sink.line}:${p.stored ?? ""}`;
    if (!groups.has(key)) groups.set(key, { sink, paths: [], omitted: 0, contrast: [], ...(p.stored ? { stored: p.stored } : {}) });
    const group = groups.get(key)!;
    if (group.paths.length < MAX_PATHS_PER_SINK) group.paths.push(p);
    else group.omitted++;
  }
  for (const group of groups.values()) {
    const origins = new Set(group.paths.map((p) => p.origin));
    group.contrast = paths.filter((p) => p.encoded && origins.has(p.origin)).slice(0, MAX_CONTRAST);
  }
  return [...groups.values()];
}

/** Identifies what the model is asked about: the output plus every hop of every path shown. */
export function xssGroupSignature(group: XssSinkGroup): string {
  const path = (p: XssPath) => p.hops.map((h) => `${h.kind}@${h.file}:${h.line}`).join(">");
  return `xss|${group.stored ?? ""}|${group.sink.file}:${group.sink.line}|${group.paths.map(path).join("|")}`;
}

function functionsOn(paths: XssPath[]): FunctionRef[] {
  const seen = new Map<string, FunctionRef>();
  for (const h of paths.flatMap((p) => p.hops)) {
    const key = `${h.fn.file}:${h.fn.startLine}`;
    if (!seen.has(key)) seen.set(key, h.fn);
  }
  return [...seen.values()];
}

const numbered = (p: XssPath, i: number) =>
  `Path ${i + 1}:\n${p.hops.map((h, n) => `  ${n + 1}. [${h.kind}] ${formatHop(h)}`).join("\n")}`;

/** Who receives the output: from Stage 1 for a stored value; a reflected value reaches only a victim lured by a link. */
export type XssReach = Reach["level"] | "crafted-link";

const WIDEST: XssReach[] = ["public", "authenticated", "own-scope"];

/** The group's reach: the widest of its paths' (stored), or a crafted link (reflected). */
export function xssReach(group: XssSinkGroup): { level: XssReach; reach?: Reach } {
  if (!group.stored) return { level: "crafted-link" };
  const reaches = group.paths.map((p) => p.reach).filter((r): r is Reach => r !== undefined);
  const reach = WIDEST.map((l) => reaches.find((r) => r.level === l)).find((r) => r !== undefined);
  return reach ? { level: reach.level, reach } : { level: "public" }; // unknown: assume the page is reachable by anyone
}

/** The ordered XSS severity rule: stored and reaching beyond the writer's own scope is critical; otherwise high. */
export function xssSeverity(group: XssSinkGroup): Severity {
  const { level } = xssReach(group);
  return level === "public" || level === "authenticated" ? "critical" : "high";
}

function reachText(group: XssSinkGroup): string {
  const { level, reach } = xssReach(group);
  const route = reach?.route ? `${reach.route} ` : "the route ";
  const serves = group.paths[0].context === "dom-html" ? "serves the stored value to the browser code that renders it" : "renders the stored value";
  switch (level) {
    case "crafted-link":
      return "crafted link — reflected input: the script runs only for a victim who opens an attacker-crafted link or page.";
    case "public":
      return `public — ${route}${serves}, and its handler${reach ? ` (${reach.at})` : ""} reads no authenticated identity: anyone who opens it receives it, including anonymous visitors.`;
    case "authenticated":
      return `any signed-in user — ${route}${serves}; it reads an authenticated identity (${reach!.at}: ${reach!.code}) but does not restrict the record to it, so other users and tenants receive it.`;
    case "own-scope":
      return `the owning scope only — ${route}${serves} and restricts the record to the caller's identity (${reach!.at}: ${reach!.code}): only users within the scope that owns the record — the writer's own scope — receive it.`;
  }
}

/** The XSS severity rule, stated as a rule with this output's reach and resulting level — applied, not re-derived. */
function severityRule(group: XssSinkGroup): string {
  return `VIEWER REACH (from Stage 1, read from the code of the route that ${group.stored ? "renders or serves the stored value" : "reflects the input"}): ${reachText(group)}

SEVERITY — XSS rule. Check these IN ORDER and assign the FIRST one that matches, using the VIEWER REACH above:
1. "critical" — stored XSS whose output reaches viewers outside the writer's own scope: anonymous or public visitors (reach: public), or other signed-in users and tenants (reach: any signed-in user). The payload persists and runs in victims' browsers without them doing anything special.
2. "high" — stored XSS whose output reaches only the writer's own scope (reach: the owning scope only), OR reflected XSS (reach: crafted link) — a victim must open an attacker-crafted link.
3. "medium" or "low" — only for a specific reason visible in the code that limits the payload itself (e.g. a partial neutralization), stated in the explanation.
The level follows from this rule and the reach above — do not re-derive impact. For this output the rule gives "${xssSeverity(group)}". State the reach in the explanation.`;
}

/** What kind of output the paths end at, in the words the judge needs. */
const OUTPUT_KIND: Record<XssPath["context"], string> = {
  markup: "interpolated or concatenated into a string whose literal text is HTML markup, which the server sends as a page",
  response: "written to the HTTP response as-is",
  "dom-html": "inserted into the page as HTML in the browser (React dangerouslySetInnerHTML, or innerHTML / insertAdjacentHTML / document.write), where the string is parsed as markup",
  "jsx-text": "rendered as a JSX text child",
};

/** The full HTTP routes the paths enter through (mount prefixes included), for example URLs grounded in the real path. */
function routesOf(group: XssSinkGroup): string {
  const routes = [...new Set(group.paths.map((p) => p.route).filter((r): r is string => r !== undefined))];
  if (routes.length === 0) return "";
  return `\nHTTP ROUTE${routes.length > 1 ? "S" : ""} (full path, including the prefix the router is mounted under): ${routes.join(", ")}`;
}

/** What the explanation and patch may rely on: the numbered code, the traced locations and routes, nothing assumed. */
function grounding(group: XssSinkGroup): string {
  const path = group.paths[0];
  const [source, sink] = [path.hops[0], path.hops.at(-1)!];
  return `GROUNDING — the explanation and patch must stay within the evidence above:
- Line numbers: cite only line numbers that appear in the numbered CODE above, exactly as shown — never approximate or guess. The tracer's locations are authoritative: the input enters at ${source.file}:${source.line} and the output is at ${sink.file}:${sink.line}; any reference to them must use these lines.
- Example URLs: build them from the HTTP route given above, in full — keep every path segment, including the mount prefix — and fill path parameters with plausible values. Do not shorten the path or invent segments.
- Facts: state only what the code and paths above show. Do not assert how requests are authenticated, how sessions are kept, or anything about cookies, headers or tokens unless that code is shown; refer to "an authenticated request" or "the victim's session" instead.`;
}

/** For stored XSS: the two requests, and where the paths cross from one to the other. */
function storedNote(group: XssSinkGroup): string {
  if (!group.stored) return "";
  const writer = group.paths.find((p) => p.writtenBy)?.writtenBy;
  return `\n\nThis is a STORED flow across two requests: request input is written to the database column ${group.stored}${writer ? ` by ${writer}` : ""}, and a later request reads that column back and renders it. In each path, the hops up to [store] are the write; [entry] and [load] mark where the rendering side begins and reads the stored value back; the rest is how it reaches the output. Anyone who can make the write controls what every later viewer receives. Check the write side for validation or encoding before storage as well as the render side.`;
}

export function buildXssPrompt(group: XssSinkGroup): string {
  const paths = group.paths.map(numbered).join("\n\n");
  const contrast =
    group.contrast.length > 0
      ? `\n\nOTHER OUTPUTS OF THE SAME INPUT — Stage 1 found these encoded or escaped on the way (${group.contrast
          .map((p) => p.encoder)
          .filter(Boolean)
          .filter((e, i, all) => all.indexOf(e) === i)
          .join("; ")}). They are NOT under review; they are shown so you can compare how the code treats this input elsewhere:\n${group.contrast
          .map((p) => `  - ${formatHop(p.hops.at(-1)!)}`)
          .join("\n")}`
      : "";
  const imports = group.paths[0].sinkImports;

  const kind = OUTPUT_KIND[group.paths[0].context];
  return `You are a senior security code reviewer. A deterministic cross-file tracer followed HTTP request input through the function calls below until it reached an HTML output — here: ${kind}. The tracer follows values across files and recognizes some encoding steps, but it over-approximates. Decide whether this is genuinely exploitable cross-site scripting (CWE-79): can an attacker, by choosing the input, make a victim's browser run script?${storedNote(group)}

The heart of the decision is whether the value is HTML-encoded or sanitized ON THE WAY TO THIS OUTPUT. Check every hop of every path. A path is NOT exploitable if, anywhere along it:
- the value is HTML-encoded for the context it lands in (& < > " ' replaced with character entities — by a project helper or a library function), or passed through an HTML sanitizer that strips script-capable markup;
- the value is converted to a number or boolean, or validated against a fixed allowlist or a strict pattern that excludes markup characters;
- the output is never interpreted as HTML (e.g. it is sent as JSON or with a non-HTML content type, or the string is only used as plain text).
Encoding applied to a DIFFERENT output of the same value does not protect this one. Judge only the output the paths below end at.
A path IS exploitable if attacker-controlled text reaches this output without such neutralization. Consider the context it lands in: element content, a quoted or unquoted attribute value, a URL-valued attribute (javascript: URLs), or inside a <script> or <style> element.

CANDIDATE PATHS (all end at the same output: ${formatHop(group.sink)})${routesOf(group)}
${paths}${group.omitted > 0 ? `\n\n(${group.omitted} more path(s) into this output are not shown.)` : ""}${contrast}

IMPORTS OF ${group.sink.file}
${imports.length > 0 ? imports.map((i) => `  ${i}`).join("\n") : "  (none)"}

CODE — every function on the paths, with real file line numbers prefixed as "N | "
${functionsOn(group.paths).map(codeSlice).join("\n\n")}

${severityRule(group)}

${grounding(group)}

OUTPUT
Return ONLY a JSON array — no prose, no markdown fences.
- [] if no path is exploitable.
- Otherwise exactly ONE object (one finding for this output):
{
  "type": "${xssType(group)}",
  "cwe": "${XSS_CWE}",
  "severity": "critical" | "high" | "medium" | "low",
  "path": number,            // the "Path N" number above that most clearly demonstrates the flaw
  "explanation": string,     // plain language: why it is exploitable across these files and what an attacker could do (include an example payload; any example URL uses the full HTTP route above), AND confirm, hop by hop, that no encoding or sanitization is applied on the way to this output${group.stored ? `; say that the input is stored (persisted)` : ""}; state the viewer reach
  "suggestedPatch": string   // corrected code for the function containing the output, HTML-encoding the value where it enters the markup — reuse an encoding helper the project already imports, if there is one — multi-line and formatted like the original
}
Do not include file, line, or taintPath fields — the tool fills those in from the traced path.`;
}

/**
 * Parses the judge's reply into one Finding (or null when it judged the paths not exploitable). Severity follows the
 * XSS rule: critical/high is the rule's level for this output's reach; only a medium/low downgrade, which the rule
 * reserves for a stated reason in the code, is taken from the model.
 */
export function parseXssJudgment(raw: string, group: XssSinkGroup): Finding | null {
  const items = extractJsonArray(raw);
  if (items.length === 0) return null;
  try {
    const judgment = validateJudgment(items[0], 0);
    const n = Number((items[0] as Record<string, unknown>).path);
    const path = (Number.isInteger(n) && group.paths[n - 1]) || group.paths[0];
    const source = path.hops[0];
    const sink = path.hops.at(-1)!;
    const severity = judgment.severity === "critical" || judgment.severity === "high" ? xssSeverity(group) : judgment.severity;
    return {
      ...judgment,
      severity,
      type: xssType(group),
      cwe: XSS_CWE,
      file: source.file,
      sourceLine: source.line,
      ...(sink.file !== source.file ? { sinkFile: sink.file } : {}),
      sinkLine: sink.line,
      taintPath: path.hops.map(formatHop),
      ...(path.route ? { httpRoute: path.route } : {}),
      confidence: "suspected",
    };
  } catch (err) {
    throw new FindingParseError(`judge response does not match the expected schema: ${(err as Error).message}`, raw);
  }
}

/** Sends one output group to the model and returns its finding, if any. */
export async function judgeXssGroup(group: XssSinkGroup): Promise<Finding | null> {
  return parseXssJudgment(await complete(buildXssPrompt(group)), group);
}
