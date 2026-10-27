// Shared types: the Finding schema — the contract every detection produces.

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["confirmed", "suspected"] as const;
/** "suspected" until the self-verification pass promotes a finding to "confirmed". */
export type Confidence = (typeof CONFIDENCES)[number];

export interface Finding {
  /** Optional external reference (e.g. a tracker or fixture id). */
  id?: string;
  /** Vulnerability class, e.g. "SQL Injection". */
  type: string;
  /** CWE identifier, e.g. "CWE-89". */
  cwe: string;
  severity: Severity;
  /** Path of the analyzed file. */
  file: string;
  /** 1-based line where untrusted input enters. */
  sourceLine: number;
  /** 1-based line where the tainted value reaches the dangerous operation. */
  sinkLine: number;
  /** Hops from source to sink, as short code descriptions. */
  taintPath: string[];
  /** Plain-language reason the flow is exploitable. */
  explanation: string;
  /** Corrected code for the sink. */
  suggestedPatch: string;
  confidence: Confidence;
}
