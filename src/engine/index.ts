// Analysis engine: single-file SQL injection detection via Muse Spark (cross-file tracing and verification come later).
import { readFile } from "node:fs/promises";
import { complete } from "../llm/meta-client.js";
import type { Finding } from "../types/index.js";
import { parseFindings } from "./parse.js";
import { buildSqliPrompt } from "./prompt.js";

export { FindingParseError } from "./parse.js";

/** Reads one file, asks the model for SQL injection findings, and returns them validated. */
export async function analyzeFile(filePath: string): Promise<Finding[]> {
  const source = await readFile(filePath, "utf8");
  const raw = await complete(buildSqliPrompt(filePath, source));
  return parseFindings(raw, filePath);
}
