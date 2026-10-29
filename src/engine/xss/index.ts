// XSS analysis: Stage 1 traces request input — directly, or stored and read back — to HTML output across files and
// into browser code; Stage 2 has the model judge each raw output.
import type { Finding } from "../../types/index.js";
import { formatHop } from "../crossfile/judge.js";
import { groupXssBySink, judgeXssGroup, xssGroupSignature, type XssSinkGroup } from "./judge.js";
import { traceXssProject, type XssTraceResult } from "./trace.js";

export { buildXssPrompt, groupXssBySink, parseXssJudgment, xssGroupSignature, xssType, XSS_CWE, XSS_STORED_TYPE, XSS_TYPE, type XssSinkGroup } from "./judge.js";
export { sqlRead, sqlWrite, traceXssProject, XssTracer, type TaintState, type XssContext, type XssPath, type XssTraceResult } from "./trace.js";

export interface XssJudgeResult {
  findings: Finding[];
  failures: { sink: string; error: unknown }[];
  /** Outputs judged, and model calls actually made (identical groups share one call). */
  sinks: number;
  calls: number;
}

/** Model calls in flight at once during a scan. */
const CONCURRENCY = 3;

/** Stage 2 over a finished trace: one model call per HTML output reached by raw input. */
export async function judgeXss(
  trace: XssTraceResult,
  judge: (group: XssSinkGroup) => Promise<Finding | null> = judgeXssGroup,
): Promise<XssJudgeResult> {
  const groups = groupXssBySink(trace.xss);
  const cache = new Map<string, Promise<Finding | null>>();
  const results: ({ finding: Finding | null } | { error: unknown })[] = new Array(groups.length);
  let next = 0;
  const worker = async () => {
    while (next < groups.length) {
      const i = next++;
      const key = xssGroupSignature(groups[i]);
      if (!cache.has(key)) cache.set(key, judge(groups[i]));
      try {
        results[i] = { finding: await cache.get(key)! };
      } catch (error) {
        results[i] = { error };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, groups.length) }, worker));

  const findings: Finding[] = [];
  const failures: XssJudgeResult["failures"] = [];
  results.forEach((r, i) => {
    if ("error" in r) failures.push({ sink: formatHop(groups[i].sink), error: r.error });
    else if (r.finding) findings.push(r.finding);
  });
  return { findings, failures, sinks: groups.length, calls: cache.size };
}

/** Runs both stages over every entry point of a project directory. */
export async function analyzeXss(dir: string): Promise<{ trace: XssTraceResult; result: XssJudgeResult }> {
  const trace = traceXssProject(dir);
  return { trace, result: await judgeXss(trace) };
}
