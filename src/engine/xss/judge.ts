// Stage 2 of XSS analysis: the model judges whether request input reaching an HTML output is exploitable XSS.
// Locations and taintPath come from the deterministic tracer; the model only decides and explains, and the heart of
// that decision is whether the value is HTML-encoded or sanitized on the way to this particular output.
import { complete } from "../../llm/meta-client.js";
import type { Finding } from "../../types/index.js";
import { codeSlice, formatHop, MAX_PATHS_PER_SINK } from "../crossfile/judge.js";
import type { FunctionRef, Hop } from "../crossfile/trace.js";
import { extractJsonArray, FindingParseError, validateJudgment } from "../parse.js";
import { SEVERITY_GUIDE } from "../prompt.js";
import type { XssPath } from "./trace.js";

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

/** How the ordered severity rules apply when the impact is script running in a victim's browser. */
const XSS_SEVERITY = `For cross-site scripting, read the rules in terms of what injected script can do in a victim's browser on this origin: act with the victim's session (cookies, tokens held by the page, authenticated requests), read what the victim can see, or perform actions as them. A reflected XSS only runs when a victim opens an attacker-crafted link or page — that is a precondition, so "exploitable without authentication" in rule 1 does not apply merely because the vulnerable page is public. State what a victim's session on this origin could reach, and the reasoning behind the severity.`;
const XSS_STORED_SEVERITY = `A stored XSS needs no crafted link: it runs for every viewer of the page or screen that renders the stored value, which typically raises severity — weigh who views it (anonymous visitors, other users, staff or administrators) and who can write it.`;

/** What kind of output the paths end at, in the words the judge needs. */
const OUTPUT_KIND: Record<XssPath["context"], string> = {
  markup: "interpolated or concatenated into a string whose literal text is HTML markup, which the server sends as a page",
  response: "written to the HTTP response as-is",
  "dom-html": "inserted into the page as HTML in the browser (React dangerouslySetInnerHTML, or innerHTML / insertAdjacentHTML / document.write), where the string is parsed as markup",
  "jsx-text": "rendered as a JSX text child",
};

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

CANDIDATE PATHS (all end at the same output: ${formatHop(group.sink)})
${paths}${group.omitted > 0 ? `\n\n(${group.omitted} more path(s) into this output are not shown.)` : ""}${contrast}

IMPORTS OF ${group.sink.file}
${imports.length > 0 ? imports.map((i) => `  ${i}`).join("\n") : "  (none)"}

CODE — every function on the paths, with real file line numbers prefixed as "N | "
${functionsOn(group.paths).map(codeSlice).join("\n\n")}

${SEVERITY_GUIDE}
${XSS_SEVERITY}${group.stored ? `\n${XSS_STORED_SEVERITY}` : ""}
Route registration and middleware are not shown; state any assumption you make about who can reach the page and who would view it.

OUTPUT
Return ONLY a JSON array — no prose, no markdown fences.
- [] if no path is exploitable.
- Otherwise exactly ONE object (one finding for this output):
{
  "type": "${xssType(group)}",
  "cwe": "${XSS_CWE}",
  "severity": "critical" | "high" | "medium" | "low",
  "path": number,            // the "Path N" number above that most clearly demonstrates the flaw
  "explanation": string,     // plain language: why it is exploitable across these files and what an attacker could do (include an example payload), AND confirm, hop by hop, that no encoding or sanitization is applied on the way to this output${group.stored ? `; say that the input is stored (persisted) and who it reaches` : ""}
  "suggestedPatch": string   // corrected code for the function containing the output, HTML-encoding the value where it enters the markup — reuse an encoding helper the project already imports, if there is one — multi-line and formatted like the original
}
Do not include file, line, or taintPath fields — the tool fills those in from the traced path.`;
}

/** Parses the judge's reply into one Finding (or null when it judged the paths not exploitable). */
export function parseXssJudgment(raw: string, group: XssSinkGroup): Finding | null {
  const items = extractJsonArray(raw);
  if (items.length === 0) return null;
  try {
    const judgment = validateJudgment(items[0], 0);
    const n = Number((items[0] as Record<string, unknown>).path);
    const path = (Number.isInteger(n) && group.paths[n - 1]) || group.paths[0];
    const source = path.hops[0];
    const sink = path.hops.at(-1)!;
    return {
      ...judgment,
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
