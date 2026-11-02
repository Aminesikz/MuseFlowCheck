// Compares two `scan --json` outputs of the same target: every structured field must match (detection, severity,
// locations, taint path, confidence, verification outcome, analysis coverage); only the model's prose may differ.
// Also checks the second run's explanations for wording leaks: prompt labels, first person, reach labels as fragments.
//
//   npx tsx scripts/compare-scans.ts <before.json> <after.json> [--show <n>]
//
// Exits 0 when the structured fields match and no explanation leaks; 1 otherwise. Suggested patches are model output
// and vary between any two runs, so they are counted, not compared.
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types/index.js";

const [beforePath, afterPath] = process.argv.slice(2).filter((a, i, all) => !a.startsWith("--") && all[i - 1] !== "--show");
const showAt = process.argv.indexOf("--show");
const show = showAt > 0 ? Number(process.argv[showAt + 1]) : 3;
if (!beforePath || !afterPath) {
  console.error("usage: npx tsx scripts/compare-scans.ts <before.json> <after.json> [--show <n>]");
  process.exit(2);
}

interface Scan {
  findings: Finding[];
  analysis: Record<string, unknown>;
}
const load = (p: string) => JSON.parse(readFileSync(p, "utf8")) as Scan;
const [before, after] = [load(beforePath), load(afterPath)];

/** Where a finding is: its class and sink, and the route it enters through. */
const key = (f: Finding) => [f.type, f.cwe, f.file, f.sinkFile ?? f.file, f.sinkLine, f.httpRoute ?? ""].join(" | ");
/** Every field except the model's prose (explanation, suggestedPatch) and the verification's free-text evidence. */
const structured = (f: Finding) => ({
  type: f.type,
  cwe: f.cwe,
  severity: f.severity,
  file: f.file,
  sourceLine: f.sourceLine,
  sinkFile: f.sinkFile,
  sinkLine: f.sinkLine,
  taintPath: f.taintPath,
  httpRoute: f.httpRoute,
  writeRoute: f.writeRoute,
  ownershipField: f.ownershipField,
  confidence: f.confidence,
  verification: f.verification?.outcome,
  patchProof: f.verification?.patchProof?.outcome,
});

/** Wording the explanation must not contain. */
const LEAKS: [string, RegExp][] = [
  ["prompt path label", /\b(?:Path|Paths) \d+\b|\bcandidate paths?\b|\bhop \d+\b/i],
  ["first person", /\bI (?:assume|think|believe|would|note|see|can|cannot)\b|\bI'm\b|\bI've\b|\b(?:we|our) (?:assume|can|see|note)\b/i],
  ["prompt heading", /\b(?:VIEWER REACH|ACTOR REACH|PATCH SCOPE|CANDIDATE PATHS|SEVERITY —)\b/],
  ["reach label as a fragment", /\breach(?: is| was)?\s*:?\s*(?:crafted link|public|any signed-in user|the owning scope only|crosses an ownership boundary|not established)\b/i],
  ["prompt section label", /(?:^|[\s.;])\([ABC]\)\s/],
  ["rule reference", /\b(?:rule|condition) \d\b/i],
  ["instruction echo", /\b(?:so|then) assume\b/i],
  ["dangling dash", /\s[—–-]\s*$/m],
];
const leaksIn = (text: string) => LEAKS.filter(([, re]) => re.test(text)).map(([name, re]) => `${name}: "${re.exec(text)![0].trim()}"`);

const byKey = (s: Scan) => new Map(s.findings.map((f) => [key(f), f]));
const [b, a] = [byKey(before), byKey(after)];
let problems = 0;
const fail = (line: string) => (problems++, console.log(`  ✗ ${line}`));

console.log(`Findings: ${before.findings.length} before, ${after.findings.length} after`);
for (const k of b.keys()) if (!a.has(k)) fail(`only before: ${k}`);
for (const k of a.keys()) if (!b.has(k)) fail(`only after:  ${k}`);
let patchesDiffer = 0;
for (const [k, fb] of b) {
  const fa = a.get(k);
  if (!fa) continue;
  const [sb, sa] = [structured(fb), structured(fa)];
  for (const field of Object.keys(sb) as (keyof typeof sb)[]) {
    if (JSON.stringify(sb[field]) !== JSON.stringify(sa[field])) fail(`${k}: ${field} ${JSON.stringify(sb[field])} → ${JSON.stringify(sa[field])}`);
  }
  if (fb.suggestedPatch !== fa.suggestedPatch) patchesDiffer++;
}
const severities = (s: Scan) => ["critical", "high", "medium", "low"].map((sev) => `${sev} ${s.findings.filter((f) => f.severity === sev).length}`).join(", ");
const confirmed = (s: Scan) => `${s.findings.filter((f) => f.confidence === "confirmed").length}/${s.findings.length} confirmed`;
console.log(`  before: ${severities(before)}; ${confirmed(before)}`);
console.log(`  after:  ${severities(after)}; ${confirmed(after)}`);
for (const field of ["complete", "files", "filesParsed", "entryPointsTotal", "entryPointsResolved", "callsFollowed", "unresolved"]) {
  if (JSON.stringify(before.analysis[field]) !== JSON.stringify(after.analysis[field])) fail(`analysis.${field} ${before.analysis[field]} → ${after.analysis[field]}`);
}
console.log(problems === 0 ? "  ✓ structured fields identical (findings, severities, locations, taint paths, confidence, verification, analysis)" : "");
console.log(`  suggested patches differing in wording: ${patchesDiffer} of ${b.size} (model output; not compared)`);

console.log("\nExplanation wording");
for (const [label, scan] of [["before", before], ["after", after]] as const) {
  const leaky = scan.findings.map((f) => [key(f), leaksIn(f.explanation)] as const).filter(([, l]) => l.length > 0);
  console.log(`  ${label}: ${leaky.length} of ${scan.findings.length} explanation(s) with leaks`);
  for (const [k, l] of leaky) {
    console.log(`    ${k}\n      ${l.join("; ")}`);
    if (label === "after") problems++;
  }
}

const sample = [...b.keys()].filter((k) => a.has(k)).sort((x, y) => leaksIn(b.get(y)!.explanation).length - leaksIn(b.get(x)!.explanation).length).slice(0, show);
for (const k of sample) console.log(`\n── ${k}\n  BEFORE: ${b.get(k)!.explanation}\n  AFTER:  ${a.get(k)!.explanation}`);

console.log(problems === 0 ? "\n✓ Same facts, clean wording." : `\n✗ ${problems} problem(s) — see above.`);
process.exit(problems === 0 ? 0 : 1);
