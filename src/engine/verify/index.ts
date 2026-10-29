// Self-verification stage: after analysis, prove each finding against a configured LOCAL target.
// Purely additive — with no target this stage never runs and findings keep confidence "suspected".
import type { Finding, Verification } from "../../types/index.js";
import { FindingParseError } from "../parse.js";
import { discoverCrossScopeId, fillParam, isMutating, routeParam } from "./discover.js";
import { evaluate, type RawResponse } from "./evaluate.js";
import { evidence } from "./evidence.js";
import { isAccessFinding, proveReadIdor, proveWriteIdor } from "./idor.js";
import { buildPocPrompt, parsePoc, type PocRequest } from "./poc.js";
import { Target, TargetError, type TargetResponse } from "./target.js";
import { BrowserError } from "./browser.js";
import { buildXssPocPrompt, isXssFinding, parseXssPlan, proveXss, type XssProofDeps } from "./xss.js";

export { assertLocalTarget, Target, TargetError, type AuthConfig, type FetchLike } from "./target.js";
export { buildPocPrompt, parsePoc, type Poc } from "./poc.js";
export { emptyResult, evaluate, findField, parse, sameResponse } from "./evaluate.js";
export { discoverCrossScopeId, fillParam, isMutating, routeParam, type RouteParam } from "./discover.js";
export { isAccessFinding, proveReadIdor, proveWriteIdor } from "./idor.js";
export { type PatchProver, verifyPatch } from "./patch.js";
export { BrowserError, DETECT_GLOBAL, ExecBrowser, type BrowserAuth, type BrowserOptions, type LoadResult } from "./browser.js";
export {
  buildXssPocPrompt,
  isXssFinding,
  MARKER_PLACEHOLDER,
  parseXssPlan,
  proveXss,
  type BrowserLike,
  type XssPlan,
  type XssProof,
  type XssProofDeps,
} from "./xss.js";
export type { Finding } from "../../types/index.js";

/** Model call plus optional context/patch-proof; injectable so the stage is testable without a network. */
export interface VerifyDeps {
  complete: (prompt: string) => Promise<string>;
  /** Describes the configured token's own scope, passed to the PoC prompt (e.g. "it belongs to tenant/shop 1"). */
  identityHint?: string;
  /**
   * When present, re-runs the confirmed PoC against a patched copy of the project (patch proof). `originalBaseline`
   * is the benign response from the unpatched target, which the patched copy must reproduce.
   */
  patchProof?: (
    finding: Finding,
    poc: { baseline: PocRequest; exploit: PocRequest; check: ReturnType<typeof parsePoc>["check"]; originalBaseline: RawResponse },
  ) => Promise<Verification["patchProof"]>;
  /** When present, enables bounded cross-scope id discovery for ":id"-style IDOR findings (probe ids 1..range). */
  probe?: { range: number };
  /** When present, XSS findings are proved by executing a payload in a headless browser; otherwise they stay suspected. */
  xss?: XssProofDeps;
}

/** Attaches a verification result to a copy of `finding`, setting confidence to confirmed or unverified. */
export async function verifyFinding(finding: Finding, target: Target, deps: VerifyDeps): Promise<Finding> {
  const unverified = (summary: string, extra: Partial<Verification> = {}): Finding => ({
    ...finding,
    confidence: "unverified",
    verification: { outcome: "unverified", summary, ...extra },
  });

  // XSS is proved by executing a payload in a headless browser, not by the request/response PoC oracle below.
  // Without a configured browser the stage is purely additive: the finding keeps its "suspected" confidence.
  if (isXssFinding(finding)) {
    if (!deps.xss) return finding;
    let plan;
    try {
      plan = parseXssPlan(await deps.complete(buildXssPocPrompt(finding, deps.identityHint)));
    } catch (err) {
      if (err instanceof FindingParseError) return unverified(`could not generate a usable XSS payload: ${err.message}`);
      throw err;
    }
    try {
      const proof = await proveXss(finding, plan, target, deps.xss);
      if (proof.kind === "confirmed") return { ...finding, confidence: "confirmed", verification: proof.verification };
      const ev = proof.verification ? { baseline: proof.verification.baseline, exploit: proof.verification.exploit } : {};
      return unverified(proof.reason, ev);
    } catch (err) {
      if (err instanceof TargetError) throw err;
      if (err instanceof BrowserError) return unverified(`the XSS execution proof could not run: ${err.message}`);
      return unverified(`the XSS proof could not be executed against the target: ${(err as Error).message}`);
    }
  }

  let poc;
  try {
    poc = parsePoc(await deps.complete(buildPocPrompt(finding, deps.identityHint)));
  } catch (err) {
    if (err instanceof FindingParseError) return unverified(`could not generate a usable PoC: ${err.message}`);
    throw err; // API/transport errors propagate; the caller decides how to report them
  }

  // ":id"-style IDOR: the owner/scope field the model's check compares, and the route's path parameter.
  const rp = routeParam(finding.httpRoute);
  const idorField = poc.check.type === "field-differs" ? poc.check.field : undefined;

  // A cross-scope WRITE is proved up front, before the generic (state-changing) exploit request is ever sent, so the
  // proof controls every mutation and can restore what it changes.
  if (deps.probe && isAccessFinding(finding) && rp && idorField && isMutating(rp.method)) {
    try {
      const proof = await proveWriteIdor(poc, rp, idorField, target, deps.probe.range);
      return proof.kind === "confirmed" ? { ...finding, confidence: "confirmed", verification: proof.verification } : unverified(proof.reason);
    } catch (err) {
      if (err instanceof TargetError) throw err;
      return unverified(`the IDOR write proof could not be executed against the target: ${(err as Error).message}`);
    }
  }

  let baseline: TargetResponse;
  let exploit: TargetResponse;
  try {
    baseline = await send(target, poc.baseline);
    exploit = await send(target, poc.exploit);
  } catch (err) {
    if (err instanceof TargetError) throw err; // a bad target is a configuration error, not a per-finding outcome
    return unverified(`the PoC could not be executed against the target: ${(err as Error).message}`);
  }

  const result = evaluate(poc.check, baseline, exploit);
  const baseEv = evidence(baseline);
  const exploitEv = evidence(exploit);
  if (!result.success) {
    // Read IDOR: the model's guessed victim id may belong to the caller's own scope. Discover a foreign-owned id and
    // prove it against that instead of giving up.
    if (deps.probe && isAccessFinding(finding) && rp && idorField && !isMutating(rp.method)) {
      try {
        const proof = await proveReadIdor(poc, rp, idorField, target, baseline, deps.probe.range);
        if (proof.kind === "confirmed") return { ...finding, confidence: "confirmed", verification: proof.verification };
        return unverified(proof.reason, { baseline: baseEv, exploit: exploitEv });
      } catch (err) {
        if (err instanceof TargetError) throw err; // otherwise fall through to the generic unverified result
      }
    }
    return unverified(`execution did not confirm the finding: ${result.detail}. ${poc.rationale}`, { baseline: baseEv, exploit: exploitEv });
  }

  const verification: Verification = {
    outcome: "confirmed",
    summary: `${poc.rationale} Confirmed: ${result.detail}.`,
    baseline: baseEv,
    exploit: exploitEv,
  };
  if (deps.patchProof) {
    verification.patchProof = await deps.patchProof(finding, { baseline: poc.baseline, exploit: poc.exploit, check: poc.check, originalBaseline: baseline });
  }
  return { ...finding, confidence: "confirmed", verification };
}

function send(target: Target, req: PocRequest): Promise<TargetResponse> {
  return target.request(req.method, req.path, { query: req.query, body: req.body, authenticated: req.authenticated });
}

/** Verifies findings one at a time (shared target state: a login token is exchanged once). */
export async function verifyFindings(findings: Finding[], target: Target, deps: VerifyDeps): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const f of findings) out.push(await verifyFinding(f, target, deps));
  return out;
}
