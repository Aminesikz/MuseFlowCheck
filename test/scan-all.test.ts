// Combined scan mode: `scan <dir>` (no --mode) runs SQL injection, access control and XSS in one pass. Drives the real
// CLI against a local stand-in for the model endpoint, so it is offline and deterministic: every judge prompt gets one
// generic high finding back. The single-class modes are the reference the combined run must reproduce.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { SEVERITIES, type Finding } from "../src/types/index.js";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
// One project with every class in it: the SQL, access-control and XSS fixtures side by side under one root.
const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-all-"));
const project = path.join(tmp, "app");
for (const fixture of ["project-scan", "access-project", "xss-project"]) {
  cpSync(fileURLToPath(new URL(`./${fixture}`, import.meta.url)), path.join(project, fixture), { recursive: true });
}

let model: http.Server;
let env: NodeJS.ProcessEnv;
before(async () => {
  model = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const text = JSON.stringify([{ type: "Fake finding", cwe: "CWE-0", severity: "high", path: 1, explanation: "e", suggestedPatch: "p" }]);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ id: "r", object: "response", status: "completed", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] }] }));
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", r));
  const { port } = model.address() as AddressInfo;
  env = { ...process.env, META_API_KEY: "offline-test", META_BASE_URL: `http://127.0.0.1:${port}`, META_MODEL: "fake" };
});
after(() => {
  model.close();
  rmSync(tmp, { recursive: true, force: true });
});

/** Runs the CLI from the temp dir (no project .env can redirect the model) and resolves its exit code and output. */
function run(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(tsx, [cli, ...args], { cwd: tmp, env, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
      resolve({ code: err ? ((err as { code?: number }).code ?? -1) : 0, stdout, stderr });
    });
  });
}

const bySeverity = (a: Finding, b: Finding) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);

test("scan <dir> without --mode runs all three classes: one merged Finding[], one summary, one exit code", async () => {
  const [all, sqli, access, xss] = await Promise.all([
    run("scan", project, "--json"),
    run("scan", project, "--mode", "sqli", "--json"),
    run("scan", project, "--mode", "access", "--json"),
    run("scan", project, "--mode", "xss", "--json"),
  ]);
  const parts = [sqli, access, xss].map((r) => JSON.parse(r.stdout) as Finding[]);
  for (const p of parts) assert.ok(p.length > 0, "every class has a finding in this project");

  // Exactly the single-class findings, nothing merged or dropped across classes, ordered by severity (stable).
  const merged = JSON.parse(all.stdout) as Finding[];
  assert.deepEqual(merged, parts.flat().sort(bySeverity));
  assert.equal(all.code, 1, "a high finding in any class gates the whole run");

  assert.match(all.stderr, /^Summary$/m);
  assert.equal(all.stderr.match(/^Summary$/gm)!.length, 1, "one summary for the run");
  assert.match(all.stderr, new RegExp(`^  SQL injection: {2}${parts[0].length} finding\\(s\\) \\(high ${parts[0].length}\\)`, "m"));
  assert.match(all.stderr, new RegExp(`^  Access control: ${parts[1].length} finding\\(s\\)`, "m"));
  assert.match(all.stderr, new RegExp(`^  XSS: {12}${parts[2].length} finding\\(s\\)`, "m"));
  assert.match(all.stderr, new RegExp(`^  Findings: {7}${merged.length} — critical 0, high ${merged.length}, medium 0, low 0$`, "m"));
});

test("--mode all is the directory default; a single file still defaults to SQL; --mode all needs a directory", async () => {
  const [implicit, explicit, file, allOnFile] = await Promise.all([
    run("scan", project, "--json"),
    run("scan", project, "--mode", "all", "--json"),
    run("scan", path.join(project, "project-scan", "routes", "search.js"), "--json"),
    run("scan", path.join(project, "project-scan", "routes", "search.js"), "--mode", "all"),
  ]);
  assert.equal(implicit.stdout, explicit.stdout);
  assert.match(file.stderr, /^Scanning .*search\.js for SQL injection\.\.\./m);
  assert.equal(allOnFile.code, 2);
  assert.match(allOnFile.stderr, /--mode all scans a project directory/);
});
