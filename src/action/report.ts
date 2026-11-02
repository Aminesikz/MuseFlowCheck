// GitHub Action reporting: turns the engine's `--json` output and exit code into a check verdict, inline review
// comments anchored on the PR's diff, and one summary comment. Pure functions only — the runner does the I/O — so the
// verdict and every payload can be tested offline. Detection stays in the engine; nothing here re-judges a finding.
import { createHash } from "node:crypto";
import path from "node:path";
import type { Analysis } from "../engine/coverage.js";
import { describeTarget, fixGroups, patchFile, sharedFixNote, type FixGroup } from "../report.js";
import { SEVERITIES, type Finding, type Severity } from "../types/index.js";

/** The engine's `--json` output. */
export interface ScanResult {
  findings: Finding[];
  analysis: Analysis;
}

/** The lowest severity that fails the check, or "none" to report findings without failing on them. */
export type FailOn = Severity | "none";
export const FAIL_ON: readonly FailOn[] = [...SEVERITIES, "none"];

/** The engine's exit codes (see the CLI usage). */
export const ENGINE_EXIT = { clean: 0, findings: 1, error: 2, incomplete: 3 } as const;

/**
 * pass: complete analysis, nothing at or above the threshold. findings: something at or above it. incomplete: no
 * gated finding, but the engine could not follow enough of the code to call it clean. error: the scan did not finish.
 * Only "pass" is a green check.
 */
export type Status = "pass" | "findings" | "incomplete" | "error";

export interface Verdict {
  status: Status;
  passed: boolean;
  /** Findings at or above the fail-on threshold. */
  gated: Finding[];
  /** Whether the analysis was complete; false when unknown (the engine failed before reporting it). */
  complete: boolean;
  /** One line for the check, the job summary and the PR summary comment. */
  headline: string;
}

export function isGated(f: Finding, failOn: FailOn): boolean {
  return failOn !== "none" && SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(failOn);
}

/**
 * The check verdict from the engine's exit code and its JSON (undefined when stdout was not valid output). An engine
 * error (2), an unknown code or missing output is an error whatever the findings say. Otherwise the findings are
 * gated at `failOn` — which can be stricter or looser than the engine's own high/critical gate — and an incomplete
 * analysis fails even with no findings: the engine's exit 1 masks its 3, so completeness is read from the JSON too.
 */
export function verdict(exitCode: number | null, result: ScanResult | undefined, failOn: FailOn): Verdict {
  const known = exitCode === ENGINE_EXIT.clean || exitCode === ENGINE_EXIT.findings || exitCode === ENGINE_EXIT.incomplete;
  const complete = result !== undefined && result.analysis.complete && exitCode !== ENGINE_EXIT.incomplete;
  const gated = result ? result.findings.filter((f) => isGated(f, failOn)) : [];
  if (!known || !result) {
    const why = exitCode === ENGINE_EXIT.error ? "the engine reported an error" : result ? `the engine exited with code ${exitCode}` : "the engine produced no readable result";
    return { status: "error", passed: false, gated, complete, headline: `Scan error — ${why}. This is not a clean bill of health.` };
  }
  const tail = complete ? "" : " The analysis was also INCOMPLETE.";
  if (gated.length > 0) {
    return { status: "findings", passed: false, gated, complete, headline: `${gated.length} finding(s) at or above ${failOn} — merge blocked.${tail}` };
  }
  if (!complete) {
    return { status: "incomplete", passed: false, gated, complete, headline: "INCOMPLETE ANALYSIS — not a clean bill of health. The engine could not follow enough of the code to call it clean." };
  }
  const n = result.findings.length;
  const headline =
    failOn === "none"
      ? `Analysis complete; ${n} finding(s), none gating (fail-on: none).`
      : `No findings at or above ${failOn}; analysis complete${n > 0 ? ` (${n} below the threshold)` : ""}.`;
  return { status: "pass", passed: true, gated, complete, headline };
}

// ---- anchoring findings on the diff ---------------------------------------------------------------

/** For each file in the PR, the head-side lines a review comment can be placed on (added or context lines). */
export type DiffIndex = Map<string, Set<number>>;

/** The head-side lines of a unified-diff patch that GitHub accepts review comments on. */
export function commentableLines(patch: string | undefined): Set<number> {
  const lines = new Set<number>();
  let right = 0;
  for (const text of (patch ?? "").split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (hunk) right = Number(hunk[1]);
    else if (right === 0 || text.startsWith("-") || text.startsWith("\\")) continue;
    else lines.add(right++); // "+" added or " " context
  }
  return lines;
}

/** A finding's repository-relative path: the engine reports paths relative to the scanned directory. */
export function repoPath(scanDir: string, file: string): string {
  return path.posix.normalize(path.posix.join(scanDir.split(path.sep).join("/"), file.split(path.sep).join("/"))).replace(/^\.\//, "");
}

/** Where on the PR a finding's comment goes: a line in the diff, or the file itself when only the file changed. */
export type Anchor = { path: string; line: number } | { path: string; line?: undefined };

/** "routes/x.js:12  code" → { file, line }. */
function hopLocation(hop: string): { file: string; line: number } | undefined {
  const m = /^(\S+?):(\d+)\s/.exec(hop);
  return m ? { file: m[1], line: Number(m[2]) } : undefined;
}

/**
 * The anchor for a finding's comment, or undefined when it touches nothing the PR changed. Prefers the sink line,
 * then the source line, then any taint-path hop (a PR that edits a helper in the middle of the path owns the finding
 * too); a changed file whose finding lines fall outside the diff gets a file-level comment. GitHub rejects line
 * comments outside the diff, so a finding on unchanged files is reported in the summary only.
 */
export function anchorFor(f: Finding, scanDir: string, diff: DiffIndex): Anchor | undefined {
  const places = [
    { file: f.sinkFile ?? f.file, line: f.sinkLine },
    { file: f.file, line: f.sourceLine },
    ...f.taintPath.map(hopLocation).filter((h) => h !== undefined),
  ].map((p) => ({ path: repoPath(scanDir, p.file), line: p.line }));
  const onLine = places.find((p) => diff.get(p.path)?.has(p.line));
  if (onLine) return onLine;
  const onFile = places.find((p) => diff.has(p.path));
  return onFile ? { path: onFile.path } : undefined;
}

// ---- comment bodies ---------------------------------------------------------------------------------

const MARKER = "museflowcheck";
export const SUMMARY_MARKER = `<!-- ${MARKER}:summary -->`;

/**
 * A stable id for a finding across runs: its class and taint path without line numbers, so a push that only moves
 * the code does not repost it. The path comes from the deterministic tracer, not the model.
 */
export function fingerprint(f: Finding): string {
  const hops = f.taintPath.map((h) => h.replace(/^(\S+?):\d+\s+/, "$1 "));
  const key = [f.type, f.cwe, f.file, f.sinkFile ?? f.file, f.httpRoute ?? "", ...hops].join("\n");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

export function findingMarker(f: Finding): string {
  return `<!-- ${MARKER}:finding:${fingerprint(f)} -->`;
}

/** The fingerprints already posted, read back from existing comment bodies. */
export function postedFingerprints(bodies: string[]): Set<string> {
  const re = new RegExp(`<!-- ${MARKER}:finding:([0-9a-f]+) -->`, "g");
  return new Set(bodies.flatMap((b) => [...b.matchAll(re)].map((m) => m[1])));
}

const BADGE: Record<Severity, string> = { critical: "🔴 **CRITICAL**", high: "🟠 **HIGH**", medium: "🟡 **MEDIUM**", low: "⚪ **LOW**" };

/** A fenced block that a backtick run inside the code cannot close early. */
function fence(code: string, lang = ""): string {
  const ticks = "`".repeat(Math.max(3, ...[...code.matchAll(/`+/g)].map((m) => m[0].length + 1)));
  return `${ticks}${lang}\n${code.replace(/\s+$/, "")}\n${ticks}`;
}

const CONFIDENCE: Record<Finding["confidence"], string> = {
  suspected: "suspected — detection only, not executed",
  confirmed: "✅ exploit confirmed against the target",
  unverified: "not confirmed by verification",
};

const FIX_TOGETHER = "**⚠ Fix together.**";

/** The same-handler warning line of a finding's comment, or undefined when its fix shares its target with no other. */
export function fixTogetherLine(f: Finding, scanDir: string, group: FixGroup | undefined): string | undefined {
  return group ? `> ${FIX_TOGETHER} ${sharedFixNote(f, group, (file) => repoPath(scanDir, file))}` : undefined;
}

/**
 * Whether a comment posted on an earlier run carries a stale same-handler warning — missing, outdated, or no longer
 * true — so the runner edits it. Nothing else triggers an edit: the model's wording varies between runs.
 */
export function staleFixNote(body: string, f: Finding, scanDir: string, group: FixGroup | undefined): boolean {
  const line = fixTogetherLine(f, scanDir, group);
  return line ? !body.includes(line) : body.includes(FIX_TOGETHER);
}

/**
 * One finding as a review comment: badge, type and CWE, location, taint path, why, proof (if any), and the fix —
 * preceded by a warning when other findings' fixes rewrite the same handler or function (`group`).
 */
export function findingComment(f: Finding, scanDir: string, anchor?: Anchor, group?: FixGroup): string {
  const source = `${repoPath(scanDir, f.file)}:${f.sourceLine}`;
  const sink = `${repoPath(scanDir, f.sinkFile ?? f.file)}:${f.sinkLine}`;
  const lines = [
    findingMarker(f),
    `${BADGE[f.severity]} · **${f.type}** · ${f.cwe}`,
    "",
    `${f.httpRoute ? `\`${f.httpRoute}\`${f.writeRoute ? ` (stored via \`${f.writeRoute}\`)` : ""} · ` : ""}\`${source}\` → \`${sink}\` · _${CONFIDENCE[f.confidence]}_`,
  ];
  if (anchor && anchor.line === undefined) lines.push("", `_This file changed in the PR, but the flow's lines are outside the diff._`);
  lines.push("", "**Taint path**", fence(f.taintPath.map((h, i) => `${i + 1}. ${repoPathInHop(h, scanDir)}`).join("\n")));
  lines.push("", "**Why**", f.explanation.trim());
  const v = f.verification;
  if (v) {
    lines.push("", v.outcome === "confirmed" ? "**Proof**" : `**Verification** (${v.outcome})`, v.summary.trim());
    if (v.patchProof) lines.push("", `Patch check: **${v.patchProof.outcome}** — ${v.patchProof.summary}`);
  }
  const together = fixTogetherLine(f, scanDir, group);
  if (together) lines.push("", "> [!WARNING]", together);
  const target = patchFile(f);
  const ext = path.extname(target ?? f.sinkFile ?? f.file).slice(1);
  lines.push("", `**Suggested fix**${target ? ` for \`${repoPath(scanDir, target)}\`` : ""}`, fence(f.suggestedPatch, ext === "ts" || ext === "tsx" ? "ts" : "js"));
  return lines.join("\n");
}

function repoPathInHop(hop: string, scanDir: string): string {
  const at = hopLocation(hop);
  return at ? hop.replace(/^\S+?:/, `${repoPath(scanDir, at.file)}:`) : hop;
}

const STATUS_ICON: Record<Status, string> = { pass: "✅", findings: "❌", incomplete: "⚠️", error: "❌" };

export interface SummaryInput {
  verdict: Verdict;
  result?: ScanResult;
  failOn: FailOn;
  scanDir: string;
  /** Fingerprints of findings that have an inline comment on this PR (posted now or on an earlier run). */
  inline: Set<string>;
  /** Why inline comments are missing, when they could not be posted at all. */
  inlineNote?: string;
  /** A link to the workflow run with the full log. */
  runUrl?: string;
}

/** The incomplete-analysis block: what was not followed and why, so "0 findings" cannot be read as a pass. */
function incompleteBlock(a: Analysis): string[] {
  const out = [
    "> [!CAUTION]",
    "> Code the engine could not follow was not checked, so the absence of findings below does not mean the code is safe.",
    ">",
    ...a.problems.map((p) => `> - ${p}`),
  ];
  if (a.reasons.length > 0) {
    out.push(">", "> Not followed (unsupported code patterns):");
    for (const r of a.reasons.slice(0, 6)) out.push(`> - ${r.count}× ${r.reason}${r.names.length > 0 ? ` (${r.names.slice(0, 5).join(", ")})` : ""} — e.g. \`${r.example}\``);
  }
  out.push(">", `> A scan is incomplete when more than ${a.maxUnresolvedPercent}% of routes, tainted calls or files went unanalyzed (the \`max-unresolved\` input).`);
  return out;
}

/** The once-per-PR summary comment (updated in place on each run): verdict, counts by class and severity, coverage. */
export function summaryComment(s: SummaryInput): string {
  const { verdict: v, result } = s;
  const out = [SUMMARY_MARKER, `## ${STATUS_ICON[v.status]} MuseFlowCheck — ${v.status === "pass" ? "passed" : v.status === "incomplete" ? "incomplete analysis" : v.status === "error" ? "scan error" : "findings"}`, "", `**${v.headline}**`, ""];
  if (result && !v.complete) out.push(...incompleteBlock(result.analysis), "");
  if (v.status === "error") out.push("> [!WARNING]", "> Part of the scan failed (for example, a sink the model could not judge), so these results are partial at best. See the workflow log for the error.", "");

  const findings = result?.findings ?? [];
  if (findings.length > 0) {
    const types = [...new Set(findings.map((f) => `${f.type} (${f.cwe})`))];
    out.push(`| Class | ${SEVERITIES.join(" | ")} | Total |`, `|---|${SEVERITIES.map(() => "--:").join("|")}|--:|`);
    for (const t of types) {
      const of = findings.filter((f) => `${f.type} (${f.cwe})` === t);
      out.push(`| ${t} | ${SEVERITIES.map((sev) => of.filter((f) => f.severity === sev).length || "·").join(" | ")} | ${of.length} |`);
    }
    out.push(`| **All** | ${SEVERITIES.map((sev) => findings.filter((f) => f.severity === sev).length || "·").join(" | ")} | **${findings.length}** |`, "");

    const groups = fixGroups(findings);
    if (groups.length > 0) {
      const where = (file: string) => repoPath(s.scanDir, file);
      out.push(
        "> [!WARNING]",
        "> **Findings that share a fix — combine their fixes.** Each suggested fix rewrites the whole handler or function on its own: applying one alone leaves the others' bugs in place, and applying them one after another conflicts.",
        ">",
      );
      for (const g of groups) {
        const members = g.findings.map((f) => `${BADGE[f.severity]} ${f.type} (${f.cwe}) at \`${where(f.sinkFile ?? f.file)}:${f.sinkLine}\``);
        out.push(`> - ${describeTarget(g.target, (file) => `\`${where(file)}\``)}: ${members.join(" · ")}`);
      }
      out.push("");
    }

    const outside = findings.filter((f) => !s.inline.has(fingerprint(f)));
    const commented = findings.length - outside.length;
    out.push(`${commented} finding(s) commented inline on this PR's diff; ${outside.length} elsewhere in the repository${s.inlineNote ? ` (${s.inlineNote})` : ""}.`, "");
    if (outside.length > 0) {
      out.push("<details><summary>Findings without an inline comment</summary>", "");
      for (const f of outside) {
        const gate = isGated(f, s.failOn) ? " **(gates)**" : "";
        out.push(`- ${BADGE[f.severity]} ${f.type} (${f.cwe})${gate}${f.httpRoute ? ` \`${f.httpRoute}\`` : ""} — \`${repoPath(s.scanDir, f.file)}:${f.sourceLine}\` → \`${repoPath(s.scanDir, f.sinkFile ?? f.file)}:${f.sinkLine}\``);
      }
      out.push("", "</details>", "");
    }
  } else if (result) out.push(v.status === "error" ? "No findings in what was scanned before the error." : v.complete ? "No findings." : "No findings in the code that could be followed.", "");

  if (result) {
    const a = result.analysis;
    const routes = a.entryPointsTotal > 0 ? `${a.entryPointsResolved} of ${a.entryPointsTotal} routes` : `${a.handlersTraced} handler(s)`;
    out.push(`**Analysis:** ${a.complete ? "complete" : "**INCOMPLETE**"} — ${routes}, ${a.callsFollowed} of ${a.callsFollowed + a.unresolved} tainted calls followed, ${a.filesParsed} of ${a.files} files parsed.`);
  }
  const confirmed = findings.some((f) => f.confidence !== "suspected");
  out.push(`**Mode:** ${confirmed ? "verified against a target" : "detection only — findings are _suspected_ (no exploit was executed)"} · fails on: \`${s.failOn}\`${s.runUrl ? ` · [workflow run](${s.runUrl})` : ""}`);
  return out.join("\n");
}
