// Checks that each multi-vector finding's suggested patch closes every one of its inputs: applies the patch to a
// throwaway copy of the scanned directory, re-runs that class's Stage 1, and lists which inputs still reach the sink.
// Offline — no model call, no server. The scanned directory is never modified.
//
//   npx tsx scripts/check-patch-vectors.ts <scan.json> <scanned dir> [--all]
//
// --all also checks single-input findings. Exits 0 when every checked patch applied and closed all its inputs; 1 when
// an input stayed open or a patch could not be applied.
import { readFileSync } from "node:fs";
import { checkPatchVectors } from "../src/engine/vector-check.js";
import type { Finding } from "../src/types/index.js";

const args = process.argv.slice(2);
const [scanPath, root] = args.filter((a) => !a.startsWith("--"));
if (!scanPath || !root) {
  console.error("usage: npx tsx scripts/check-patch-vectors.ts <scan.json> <scanned dir> [--all]");
  process.exit(2);
}
const { findings } = JSON.parse(readFileSync(scanPath, "utf8")) as { findings: Finding[] };
const checked = findings.filter((f) => args.includes("--all") || (f.vectors?.length ?? 0) > 1);

let problems = 0;
console.log(`${checked.length} of ${findings.length} finding(s) checked${args.includes("--all") ? "" : " (those with several inputs)"}`);
for (const f of checked) {
  console.log(`\n${f.type} · ${f.cwe} · ${f.severity}  ${f.httpRoute ?? f.file}  sink ${f.sinkFile ?? f.file}:${f.sinkLine}`);
  const check = checkPatchVectors(root, f);
  if (!check.applied) {
    problems++;
    console.log(`  ✗ patch not applied: ${check.reason}`);
    continue;
  }
  console.log(`  patch applied to ${check.file}; Stage 1 re-run on the patched copy:`);
  for (const v of check.vectors) {
    if (v.open) problems++;
    console.log(`    ${v.open ? "✗" : "✓"} ${v.input} ${v.open ? "still reaches the sink" : "closed"}`);
  }
}
console.log(problems === 0 ? "\n✓ Every checked patch closes all of its inputs." : `\n✗ ${problems} problem(s) — see above.`);
process.exit(problems === 0 ? 0 : 1);
