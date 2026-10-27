// Cross-file analysis: Stage 1 traces request input to SQL execution across files; Stage 2 has the model judge each sink.
import type { Finding } from "../../types/index.js";
import { groupBySink, judgeGroup } from "./judge.js";
import { traceEntry, type TraceResult } from "./trace.js";

export { buildJudgePrompt, formatHop, groupBySink } from "./judge.js";
export { findProjectRoot, traceEntry, type CandidatePath, type Hop, type TraceResult } from "./trace.js";

/** Stage 2 over a finished trace: one model call per SQL execution call reached through SQL text. */
export async function judgeTrace(trace: TraceResult): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const group of groupBySink(trace.paths)) {
    const finding = await judgeGroup(group);
    if (finding) findings.push(finding);
  }
  return findings;
}

/** Runs both stages for one entry file. */
export async function analyzeCrossFile(entry: string, root?: string): Promise<{ trace: TraceResult; findings: Finding[] }> {
  const trace = traceEntry(entry, root);
  return { trace, findings: await judgeTrace(trace) };
}
