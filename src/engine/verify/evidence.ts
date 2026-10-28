// A compact record of one real request/response, attached to a Verification as its evidence trail.
import type { EvidenceRequest } from "../../types/index.js";
import type { TargetResponse } from "./target.js";

export function excerpt(body: string, max = 300): string {
  const clean = body.replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

export function evidence(res: TargetResponse): EvidenceRequest {
  return { method: res.method, path: res.path, status: res.status, responseExcerpt: excerpt(res.body) };
}
