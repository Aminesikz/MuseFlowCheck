// Stage 2 of cross-file analysis: Muse Spark judges whether traced candidate paths are exploitable SQL injection.
// Locations and taintPath come from the deterministic tracer; the model only decides and explains.
import { complete } from "../../llm/meta-client.js";
import type { Finding } from "../../types/index.js";
import { extractJsonArray, FindingParseError, validateJudgment } from "../parse.js";
import { SAFE_PATTERNS, SEVERITY_GUIDE } from "../prompt.js";
import type { CandidatePath, FunctionRef, Hop } from "./trace.js";

/** Candidate paths into SQL text that end at the same executing call. */
export interface SinkGroup {
  sink: Hop;
  paths: CandidatePath[];
}

export function groupBySink(paths: CandidatePath[]): SinkGroup[] {
  const groups = new Map<string, SinkGroup>();
  for (const p of paths.filter((c) => c.sqlText)) {
    const sink = p.hops.at(-1)!;
    const key = `${sink.file}:${sink.line}`;
    if (!groups.has(key)) groups.set(key, { sink, paths: [] });
    groups.get(key)!.paths.push(p);
  }
  return [...groups.values()];
}

export function formatHop(h: Hop): string {
  return `${h.file}:${h.line}  ${h.code}`;
}

/** Every function on the group's paths, in first-seen order, deduplicated. */
function functionsOn(group: SinkGroup): FunctionRef[] {
  const seen = new Map<string, FunctionRef>();
  for (const p of group.paths) {
    for (const h of p.hops) {
      const key = `${h.fn.file}:${h.fn.startLine}`;
      if (!seen.has(key)) seen.set(key, h.fn);
    }
  }
  return [...seen.values()];
}

/** A function's code with its real file line numbers. */
function codeSlice(fn: FunctionRef): string {
  const numbered = fn.code.split("\n").map((line, i) => `${String(fn.startLine + i).padStart(4, " ")} | ${line}`);
  return `=== ${fn.file} — ${fn.name} (lines ${fn.startLine}–${fn.endLine}) ===\n${numbered.join("\n")}`;
}

export function buildJudgePrompt(group: SinkGroup): string {
  const paths = group.paths
    .map((p, i) => `Path ${i + 1}:\n${p.hops.map((h, n) => `  ${n + 1}. [${h.kind}] ${formatHop(h)}`).join("\n")}`)
    .join("\n\n");

  return `You are a senior security code reviewer. A deterministic cross-file tracer followed HTTP request input through the function calls below until it became part of the SQL text passed to a call that executes SQL. The tracer follows values across files, but it does NOT understand validation or sanitization — it over-approximates. Decide whether this is genuinely exploitable SQL injection (CWE-89).

Check every hop of every path. A path is NOT exploitable if, anywhere along it, the value is neutralized:
${SAFE_PATTERNS}
Also not exploitable: a condition on the path that makes the dangerous concatenation unreachable for attacker-chosen values.
A path IS exploitable if attacker-controlled data reaches the SQL text without neutralization — including as an unquoted numeric value, an identifier, or a keyword.

CANDIDATE PATHS (all end at the same SQL execution call: ${formatHop(group.sink)})
${paths}

CODE — every function on the paths, with real file line numbers prefixed as "N | "
${functionsOn(group).map(codeSlice).join("\n\n")}

${SEVERITY_GUIDE}
Middleware and route registration are not shown. If the handler reads an authenticated-user object (e.g. req.user, ctx.state.user), assume the route requires login; otherwise assume it may be reachable without authentication. State that assumption in the explanation. It only affects the "without authentication" condition of rule 1 — it never lowers severity when the data-scope condition of rule 1 matches.

OUTPUT
Return ONLY a JSON array — no prose, no markdown fences.
- [] if no path is exploitable.
- Otherwise exactly ONE object (one finding for this SQL execution call):
{
  "type": "SQL Injection",
  "cwe": "CWE-89",
  "severity": "critical" | "high" | "medium" | "low",
  "path": number,            // the "Path N" number above that most clearly demonstrates the injection
  "explanation": string,     // plain language: why it is exploitable across these files, what an attacker could do; mention any other exploitable paths into the same call
  "suggestedPatch": string   // corrected code for the function containing the SQL execution, using the same library's parameter binding, multi-line and formatted like the original
}
Do not include file, line, or taintPath fields — the tool fills those in from the traced path.`;
}

/** Parses the judge's reply into one Finding (or null when it judged the paths not exploitable). */
export function parseJudgment(raw: string, group: SinkGroup): Finding | null {
  const items = extractJsonArray(raw);
  if (items.length === 0) return null;
  try {
    const judgment = validateJudgment(items[0], 0);
    // "path" is 1-based, matching the "Path N" headings in the prompt and the trace output.
    const n = Number((items[0] as Record<string, unknown>).path);
    const path = (Number.isInteger(n) && group.paths[n - 1]) || group.paths[0];
    const source = path.hops[0];
    const sink = path.hops.at(-1)!;
    return {
      ...judgment,
      file: source.file,
      sourceLine: source.line,
      ...(sink.file !== source.file ? { sinkFile: sink.file } : {}),
      sinkLine: sink.line,
      taintPath: path.hops.map(formatHop),
      confidence: "suspected",
    };
  } catch (err) {
    throw new FindingParseError(`judge response does not match the expected schema: ${(err as Error).message}`, raw);
  }
}

/** Sends one sink group to the model and returns its finding, if any. */
export async function judgeGroup(group: SinkGroup): Promise<Finding | null> {
  return parseJudgment(await complete(buildJudgePrompt(group)), group);
}
