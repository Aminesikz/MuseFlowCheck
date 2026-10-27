// Self-verification stage: after analysis, prove each finding against a configured LOCAL target.
// Purely additive — with no target this stage never runs and findings keep confidence "suspected".
import type { EvidenceRequest, Finding, Verification } from "../../types/index.js";
import { FindingParseError } from "../parse.js";
import { evaluate } from "./evaluate.js";
import { buildPocPrompt, parsePoc, type PocRequest } from "./poc.js";
import { Target, TargetError, type TargetResponse } from "./target.js";

export { assertLocalTarget, Target, TargetError, type AuthConfig, type FetchLike } from "./target.js";
export { buildPocPrompt, parsePoc, type Poc } from "./poc.js";
export { evaluate } from "./evaluate.js";
export { type PatchProver, verifyPatch } from "./patch.js";

/** Model call plus optional context/patch-proof; injectable so the stage is testable without a network. */
export interface VerifyDeps {
  complete: (prompt: string) => Promise<string>;
  /** Describes the configured token's own scope, passed to the PoC prompt (e.g. "it belongs to tenant/shop 1"). */
  identityHint?: string;
  /** When present, re-runs the confirmed PoC against a patched copy of the project (patch proof). */
  patchProof?: (finding: Finding, poc: { baseline: PocRequest; exploit: PocRequest; check: ReturnType<typeof parsePoc>["check"] }) => Promise<Verification["patchProof"]>;
}

function excerpt(body: string, max = 300): string {
  const clean = body.replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function evidence(res: TargetResponse): EvidenceRequest {
  return { method: res.method, path: res.path, status: res.status, responseExcerpt: excerpt(res.body) };
}

/** Attaches a verification result to a copy of `finding`, setting confidence to confirmed or unverified. */
export async function verifyFinding(finding: Finding, target: Target, deps: VerifyDeps): Promise<Finding> {
  const unverified = (summary: string, extra: Partial<Verification> = {}): Finding => ({
    ...finding,
    confidence: "unverified",
    verification: { outcome: "unverified", summary, ...extra },
  });

  let poc;
  try {
    poc = parsePoc(await deps.complete(buildPocPrompt(finding, deps.identityHint)));
  } catch (err) {
    if (err instanceof FindingParseError) return unverified(`could not generate a usable PoC: ${err.message}`);
    throw err; // API/transport errors propagate; the caller decides how to report them
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
    return unverified(`execution did not confirm the finding: ${result.detail}. ${poc.rationale}`, { baseline: baseEv, exploit: exploitEv });
  }

  const verification: Verification = {
    outcome: "confirmed",
    summary: `${poc.rationale} Confirmed: ${result.detail}.`,
    baseline: baseEv,
    exploit: exploitEv,
  };
  if (deps.patchProof) verification.patchProof = await deps.patchProof(finding, { baseline: poc.baseline, exploit: poc.exploit, check: poc.check });
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
