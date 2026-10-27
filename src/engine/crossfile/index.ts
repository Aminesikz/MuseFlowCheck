// Cross-file analysis: Stage 1 traces request input to SQL execution across files; Stage 2 has the model judge each sink.
import type { Finding } from "../../types/index.js";
import { formatHop, groupBySink, groupSignature, judgeGroup, type SinkGroup } from "./judge.js";
import { traceEntry, traceProject, type TraceResult } from "./trace.js";

export { buildJudgePrompt, formatHop, groupBySink, groupSignature } from "./judge.js";
export { discoverFiles } from "./files.js";
export {
  findProjectRoot,
  traceEntry,
  traceProject,
  type CandidatePath,
  type EntryPoint,
  type ExternalCall,
  type Hop,
  type TraceResult,
  type UnresolvedCall,
} from "./trace.js";

/** A sink whose judgment failed (API error or unparseable reply); the rest of the scan still completes. */
export interface JudgeFailure {
  sink: string;
  error: unknown;
}

export interface JudgeResult {
  findings: Finding[];
  failures: JudgeFailure[];
  /** Sinks judged, and model calls actually made (identical groups share one call). */
  sinks: number;
  calls: number;
}

/** Judgments by group signature, so the same paths into the same sink are sent to the model once. */
export type JudgeCache = Map<string, Promise<Finding | null>>;

/** Model calls in flight at once during a scan. */
const CONCURRENCY = 3;

/** Stage 2 over a finished trace: one model call per SQL execution call reached through SQL text. */
export async function judgeTrace(trace: TraceResult, cache: JudgeCache = new Map()): Promise<JudgeResult> {
  const groups = groupBySink(trace.paths);
  const results: ({ finding: Finding | null } | { error: unknown })[] = new Array(groups.length);
  let calls = 0;
  const judge = (group: SinkGroup) => {
    const key = groupSignature(group);
    if (!cache.has(key)) {
      calls++;
      cache.set(key, judgeGroup(group));
    }
    return cache.get(key)!;
  };

  let next = 0;
  const worker = async () => {
    while (next < groups.length) {
      const i = next++;
      try {
        results[i] = { finding: await judge(groups[i]) };
      } catch (error) {
        results[i] = { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, groups.length) }, worker));

  const findings: Finding[] = [];
  const failures: JudgeFailure[] = [];
  results.forEach((r, i) => {
    if ("error" in r) failures.push({ sink: formatHop(groups[i].sink), error: r.error });
    else if (r.finding) findings.push(r.finding);
  });
  return { findings, failures, sinks: groups.length, calls };
}

/** Runs both stages for one entry file. */
export async function analyzeCrossFile(entry: string, root?: string): Promise<{ trace: TraceResult; result: JudgeResult }> {
  const trace = traceEntry(entry, root);
  return { trace, result: await judgeTrace(trace) };
}

/** Runs both stages over every entry point of a project directory. */
export async function analyzeProject(dir: string): Promise<{ trace: TraceResult; result: JudgeResult }> {
  const trace = traceProject(dir);
  return { trace, result: await judgeTrace(trace) };
}
