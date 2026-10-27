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

/** A findings array: empty, or every element an object. Rules out stray prose like "[1]" or "[see below]". */
function isFindingArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.every((v) => typeof v === "object" && v !== null && !Array.isArray(v));
}

/** Accepts a bare array, or an object wrapping one (e.g. {"findings": [...]}). */
function asFindingArray(value: unknown): unknown[] | undefined {
  if (isFindingArray(value)) return value;
  if (typeof value === "object" && value !== null) {
    const arrays = Object.values(value).filter(isFindingArray);
    if (arrays.length === 1) return arrays[0];
  }
  return undefined;
}

/**
 * Extracts the findings array from model output, tolerating markdown fences, surrounding prose,
 * a BOM / zero-width characters, and a wrapping object. Tries, in order: the whole text, each
 * fenced block, each balanced [...] span, then each balanced {...} span.
 */
export function extractJsonArray(raw: string): unknown[] {
  const text = raw.replace(/^﻿/, "").replace(/[​-‍⁠]/g, "");
  const candidates = [text.trim()];
  for (const match of text.matchAll(/```[a-zA-Z]*\s*([\s\S]*?)```/g)) candidates.push(match[1].trim());
  candidates.push(...balancedSpans(text, "[", "]"), ...balancedSpans(text, "{", "}"));

  for (const candidate of candidates) {
    let value: unknown;
    try {
      value = JSON.parse(candidate);
    } catch {
      continue;
    }
    const findings = asFindingArray(value);
    if (findings) return findings;
  }
  throw new FindingParseError("model response did not contain a JSON array of findings", raw);
}

/**
 * Yields each outermost balanced open…close substring, skipping brackets inside JSON strings.
 * Nested spans are never yielded on their own: if a malformed findings array fails to parse, an
 * inner fragment (e.g. an empty `"taintPath": []`) must not be mistaken for "no findings".
 */
function* balancedSpans(text: string, open: string, close: string): Generator<string> {
  let start = text.indexOf(open);
  while (start !== -1) {
    let end = -1;
    let depth = 0;
    let inString = false;
    for (let i = start; i < text.length && end === -1; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === "\\") i++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === open) depth++;
      else if (ch === close && --depth === 0) end = i;
    }
    if (end !== -1) yield text.slice(start, end + 1);
    start = text.indexOf(open, end !== -1 ? end + 1 : start + 1);
  }
}

function toLine(value: unknown, field: string, index: number, lineCount: number): number {
  const n = typeof value === "string" ? Number(value.trim().replace(/^L/i, "")) : value;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > lineCount) {
    throw new Error(`finding[${index}].${field} must be a line number between 1 and ${lineCount}, got ${JSON.stringify(value)}`);
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
 * forced to "suspected" — only the verification pass may promote a finding. Line numbers must fall
 * inside the analyzed file (`lineCount` lines).
 */
export function parseFindings(raw: string, file: string, lineCount: number): Finding[] {
  const items = extractJsonArray(raw);
  try {
    return items.map((item, i): Finding => {
      const f = item as Record<string, unknown>;

      const severity = typeof f.severity === "string" ? f.severity.trim().toLowerCase() : f.severity;
      if (!SEVERITIES.includes(severity as Severity)) {
        throw new Error(`finding[${i}].severity must be one of ${SEVERITIES.join("/")}, got ${JSON.stringify(f.severity)}`);
      }
      if (!Array.isArray(f.taintPath) || f.taintPath.length < 2) {
        throw new Error(`finding[${i}].taintPath must be an array of at least 2 hops (source → ... → execute)`);
      }

      return {
        ...(typeof f.id === "string" && f.id.trim() ? { id: f.id.trim() } : {}),
        type: toText(f.type, "type", i),
        cwe: toText(f.cwe, "cwe", i),
        severity: severity as Severity,
        file,
        sourceLine: toLine(f.sourceLine, "sourceLine", i, lineCount),
        sinkLine: toLine(f.sinkLine, "sinkLine", i, lineCount),
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
