// Shared types: the Finding schema — the contract every detection produces.

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["confirmed", "suspected", "unverified"] as const;
/**
 * Analysis reports "suspected". The self-verification pass, when a local target is configured, promotes a finding
 * to "confirmed" (its PoC demonstrably succeeded) or marks it "unverified" (execution did not confirm it).
 */
export type Confidence = (typeof CONFIDENCES)[number];

export interface Finding {
  /** Optional external reference (e.g. a tracker or fixture id). */
  id?: string;
  /** Vulnerability class, e.g. "SQL Injection". */
  type: string;
  /** CWE identifier, e.g. "CWE-89". */
  cwe: string;
  severity: Severity;
  /** Path of the analyzed file; for cross-file findings, the file containing the source. */
  file: string;
  /** 1-based line where untrusted input enters (in `file`). */
  sourceLine: number;
  /** File containing the sink, when it differs from `file` (cross-file findings). */
  sinkFile?: string;
  /** 1-based line (in `sinkFile ?? file`) of the call that executes the query (e.g. `pool.query(sql)`), not where the SQL string is built. */
  sinkLine: number;
  /**
   * Ordered hops from source to sink, each a short code excerpt with its line:
   * source → intermediate steps (assignments, helper calls, string building) → execute call.
   */
  taintPath: string[];
  /** Plain-language reason the flow is exploitable. */
  explanation: string;
  /** Corrected code for the sink. */
  suggestedPatch: string;
  /** The HTTP route the tainted input enters through, e.g. "GET /api/barbers/search", when traced from a registered handler. */
  httpRoute?: string;
  confidence: Confidence;
  /** Attached by the self-verification pass when a local target is configured; drives `confidence`. */
  verification?: Verification;
}

/** One HTTP request sent during verification, recorded as evidence. */
export interface EvidenceRequest {
  method: string;
  path: string;
  status: number;
  /** A short, truncated excerpt of the response body. */
  responseExcerpt: string;
}

/** The result of attempting to prove a finding against the configured local target. */
export interface Verification {
  /** "confirmed" when the exploit demonstrably succeeded against the baseline; "unverified" otherwise. */
  outcome: "confirmed" | "unverified";
  /** Plain-language account of what was attempted and what the comparison showed. */
  summary: string;
  /** The benign request and the exploit request, for the evidence trail. */
  baseline?: EvidenceRequest;
  exploit?: EvidenceRequest;
  /**
   * Result of re-running the PoC against a patched copy: "blocked" when the exploit stopped working and the benign
   * request returned the same response as before the patch; "breaks-route" when the exploit stopped but the benign
   * response changed; "still-exploitable" when the exploit still worked; "not-attempted" when the patch was not applied.
   */
  patchProof?: { outcome: "blocked" | "breaks-route" | "still-exploitable" | "not-attempted"; summary: string };
}
