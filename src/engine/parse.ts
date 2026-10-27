// Turns a raw model response into validated Finding objects.
import { SEVERITIES, type Finding, type Severity } from "../types/index.js";

/** Thrown when the model's reply can't be turned into Finding[]; carries the raw text for debugging. */
export class FindingParseError extends Error {
  constructor(
    message: string,
    readonly raw: string,
  ) {
    super(message);
  }
}

/**
 * Extracts the first JSON array from model output, tolerating markdown fences and surrounding prose.
 * Tries, in order: the whole text, each fenced block, then each balanced [...] span.
 */
export function extractJsonArray(raw: string): unknown[] {
  const candidates = [raw.trim()];
  for (const match of raw.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)) candidates.push(match[1].trim());
  candidates.push(...balancedArraySpans(raw));

  for (const candidate of candidates) {
    try {
      const value: unknown = JSON.parse(candidate);
      if (Array.isArray(value)) return value;
    } catch {
      // try the next candidate
    }
  }
  throw new FindingParseError("model response did not contain a JSON array", raw);
}

/** Yields every bracket-balanced substring starting at a "[", skipping brackets inside JSON strings. */
function* balancedArraySpans(text: string): Generator<string> {
  for (let start = text.indexOf("["); start !== -1; start = text.indexOf("[", start + 1)) {
    let depth = 0;
    let inString = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === "\\") i++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === "[") depth++;
      else if (ch === "]" && --depth === 0) {
        yield text.slice(start, i + 1);
        break;
      }
    }
  }
}

function toLine(value: unknown, field: string, index: number): number {
  const n = typeof value === "string" ? Number(value.trim()) : value;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1) {
    throw new Error(`finding[${index}].${field} must be a positive integer, got ${JSON.stringify(value)}`);
  }
  return n;
}

function toText(value: unknown, field: string, index: number): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`finding[${index}].${field} must be a non-empty string, got ${JSON.stringify(value)}`);
  }
  return value.trim();
}

/**
 * Validates raw model output into Finding[]. `file` is always the analyzed path, and confidence is
 * forced to "suspected" — only the verification pass may promote a finding.
 */
export function parseFindings(raw: string, file: string): Finding[] {
  const items = extractJsonArray(raw);
  try {
    return items.map((item, i): Finding => {
      if (typeof item !== "object" || item === null) throw new Error(`finding[${i}] is not an object`);
      const f = item as Record<string, unknown>;

      const severity = typeof f.severity === "string" ? f.severity.trim().toLowerCase() : f.severity;
      if (!SEVERITIES.includes(severity as Severity)) {
        throw new Error(`finding[${i}].severity must be one of ${SEVERITIES.join("/")}, got ${JSON.stringify(f.severity)}`);
      }
      if (!Array.isArray(f.taintPath) || f.taintPath.length === 0) {
        throw new Error(`finding[${i}].taintPath must be a non-empty array of strings`);
      }

      return {
        ...(typeof f.id === "string" && f.id.trim() ? { id: f.id.trim() } : {}),
        type: toText(f.type, "type", i),
        cwe: toText(f.cwe, "cwe", i),
        severity: severity as Severity,
        file,
        sourceLine: toLine(f.sourceLine, "sourceLine", i),
        sinkLine: toLine(f.sinkLine, "sinkLine", i),
        taintPath: f.taintPath.map((hop, h) => toText(hop, `taintPath[${h}]`, i)),
        explanation: toText(f.explanation, "explanation", i),
        suggestedPatch: toText(f.suggestedPatch, "suggestedPatch", i),
        confidence: "suspected",
      };
    });
  } catch (err) {
    throw new FindingParseError(`response JSON does not match the Finding schema: ${(err as Error).message}`, raw);
  }
}
