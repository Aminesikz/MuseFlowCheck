// Analysis coverage: whether a scan reached enough of the target for "no findings" to mean clean. Stage 1 records
// what it followed and where it broke; this turns that into a verdict. A scan that could not follow most of the
// routes or calls it found is incomplete, not clean — the CLI warns and exits with its own code.
import type { Coverage, ParseError, RouteRegistration, UnresolvedCall } from "./crossfile/index.js";

/** Default share (percent) of routes, tainted calls or files that may go unanalyzed before a scan is incomplete. */
export const DEFAULT_MAX_UNRESOLVED = 20;

/** One reason a route or call could not be followed, how often it occurred, and where it first did. */
export interface UnresolvedReason {
  /** The reason without the name it is about, e.g. "'new' on constructor function". */
  reason: string;
  count: number;
  /** The project functions or classes it was about, when the reason names one (e.g. the constructor functions). */
  names: string[];
  example: string;
}

/** The completeness verdict of one scan, emitted as `analysis` in the --json output. */
export interface Analysis {
  /** False when too much of the target went unanalyzed for "no findings" to be a clean bill of health. */
  complete: boolean;
  /** The threshold applied, in percent. */
  maxUnresolvedPercent: number;
  files: number;
  filesParsed: number;
  parseErrors: ParseError[];
  /** Route registrations naming project code (`app.get('/x', mw, handler)`). */
  entryPointsTotal: number;
  /** Those whose handler and every middleware resolved to a function. */
  entryPointsResolved: number;
  /** Request handlers traced, including ones found by convention rather than through a registration. */
  handlersTraced: number;
  /** Tainted calls followed into project code or a sink. */
  callsFollowed: number;
  /** Tainted calls into project code the tracer could not follow. */
  unresolved: number;
  /** Why routes and calls could not be followed, most frequent first. */
  reasons: UnresolvedReason[];
  /** Each reason the scan is incomplete; empty when complete. */
  problems: string[];
}

/** One vulnerability class's Stage 1 coverage. */
export interface ClassCoverage {
  name: string;
  coverage: Coverage;
}

const pct = (part: number, whole: number) => Math.round((part / whole) * 100);
const key = (x: { file: string; line: number; call?: string }) => `${x.file}:${x.line}:${x.call ?? ""}`;

function dedupe<T extends { file: string; line: number; call?: string }>(lists: T[][]): T[] {
  const seen = new Map<string, T>();
  for (const list of lists) for (const x of list) if (!seen.has(key(x))) seen.set(key(x), x);
  return [...seen.values()];
}

/** A registration not fully followed: its handler did not resolve, or one of its middleware did not. */
function brokenRoute(r: RouteRegistration): boolean {
  return !r.handler || r.unresolved.length > 0;
}

/** A reason that ends in the function or class it is about, split so occurrences group by kind. */
const NAMED_REASON = /^(.*\b(?:function|class)) ([\w$.<>]+)$/;

function reasonsOf(routes: RouteRegistration[], calls: UnresolvedCall[]): UnresolvedReason[] {
  const by = new Map<string, UnresolvedReason>();
  const add = (full: string, example: string) => {
    const m = NAMED_REASON.exec(full);
    const reason = m ? m[1] : full;
    const r = by.get(reason) ?? by.set(reason, { reason, count: 0, names: [], example }).get(reason)!;
    r.count++;
    if (m && !r.names.includes(m[2])) r.names.push(m[2]);
  };
  for (const r of routes) for (const reason of r.unresolved) add(reason, `${r.file}:${r.line}  ${r.route}`);
  for (const u of calls) add(u.reason, `${u.file}:${u.line}  ${u.call}`);
  return [...by.values()].sort((a, b) => b.count - a.count);
}

/**
 * Judges a scan's coverage across its classes. Incomplete when, beyond `maxUnresolved` percent: route registrations
 * were not fully followed, tainted calls into project code were not followed (overall, or within one class), or
 * files failed to parse — or when no entry point was found at all, so nothing was analyzed.
 */
export function assessCoverage(classes: ClassCoverage[], maxUnresolved = DEFAULT_MAX_UNRESOLVED): Analysis {
  const all = classes.map((c) => c.coverage);
  const files = Math.max(0, ...all.map((c) => c.files));
  const parseErrors = dedupe(all.map((c) => c.parseErrors));
  const routes = dedupe(all.map((c) => c.registrations));
  const followed = dedupe(all.map((c) => c.followed));
  const unresolved = dedupe(all.map((c) => c.unresolved));
  const handlers = Math.max(0, ...all.map((c) => c.entryPoints));
  const broken = routes.filter(brokenRoute);
  const over = (part: number, whole: number) => whole > 0 && (part / whole) * 100 > maxUnresolved;

  const problems: string[] = [];
  if (files === 0) problems.push("no source files were found");
  else if (routes.length === 0 && handlers === 0) problems.push("no request entry point (route or handler) was found — nothing was analyzed");
  if (over(broken.length, routes.length)) {
    const noHandler = broken.filter((r) => !r.handler).length;
    const parts = [noHandler > 0 ? `${noHandler} handler(s) not resolved` : "", broken.length - noHandler > 0 ? `${broken.length - noHandler} with middleware not resolved` : ""];
    problems.push(`could not follow ${broken.length} of ${routes.length} routes (${pct(broken.length, routes.length)}%) — ${parts.filter(Boolean).join(", ")}`);
  }
  const calls = followed.length + unresolved.length;
  if (over(unresolved.length, calls)) {
    problems.push(`could not follow ${unresolved.length} of ${calls} tainted calls into project code (${pct(unresolved.length, calls)}%)`);
  } else {
    // Overall coverage can hide one class whose own traces all broke.
    for (const c of classes) {
      const u = c.coverage.unresolved.length;
      const n = u + c.coverage.followed.length;
      if (over(u, n)) problems.push(`${c.name}: could not follow ${u} of ${n} tainted calls into project code (${pct(u, n)}%)`);
    }
  }
  if (over(parseErrors.length, files)) problems.push(`${parseErrors.length} of ${files} files failed to parse (${pct(parseErrors.length, files)}%)`);

  return {
    complete: problems.length === 0,
    maxUnresolvedPercent: maxUnresolved,
    files,
    filesParsed: files - parseErrors.length,
    parseErrors,
    entryPointsTotal: routes.length,
    entryPointsResolved: routes.length - broken.length,
    handlersTraced: handlers,
    callsFollowed: followed.length,
    unresolved: unresolved.length,
    reasons: reasonsOf(broken, unresolved),
    problems,
  };
}

/** The analysis of a single-file scan, which sends the whole file to the model: nothing is traced, so nothing is skipped. */
export function wholeFileAnalysis(maxUnresolved = DEFAULT_MAX_UNRESOLVED): Analysis {
  return {
    complete: true,
    maxUnresolvedPercent: maxUnresolved,
    files: 1,
    filesParsed: 1,
    parseErrors: [],
    entryPointsTotal: 0,
    entryPointsResolved: 0,
    handlersTraced: 0,
    callsFollowed: 0,
    unresolved: 0,
    reasons: [],
    problems: [],
  };
}
