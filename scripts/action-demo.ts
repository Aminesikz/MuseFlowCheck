// Runs the GitHub Action's runner locally against a project, with a stand-in GitHub API that records what the Action
// would post: the inline review comments (validated against the PR's diff the way GitHub does), the summary comment,
// the step outputs and the exit code. Nothing reaches GitHub. The project is copied to a temporary "checkout" first.
//
//   npx tsx scripts/action-demo.ts <project-dir> [--changed <file>[:<from>-<to>],...] [--fail-on <severity>]
//                                  [--runs <n>] [--seed <comments.json>] [--offline [finding|garbage]] [--json]
//
// --changed   the files the simulated PR changes (repo-relative), optionally only a line range; default: every file
// --runs      run the Action n times against the same PR, to show re-runs do not repost comments (default 1)
// --seed      review comments already on the PR before the first run (a JSON array of { path, line?, body })
// --offline   answer model calls from a local stand-in instead of the Meta Model API: "finding" (default) returns one
//             canned high finding per judged sink, "garbage" an unparsable reply (an engine error). Without
//             --offline the real API is called, with META_* from .env.
// --json      print everything recorded as JSON on stdout (used by test/action.test.ts)
import { spawn } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { commentableLines } from "../src/action/report.js";

const HEAD_SHA = "0123456789abcdef0123456789abcdef01234567";
const PR = 7;
const REPO = "demo/app";

const argv = process.argv.slice(2);
const VALUE_FLAGS = new Set(["--changed", "--fail-on", "--runs", "--seed"]);
const MODEL_MODES = ["finding", "garbage"];
const opt = (name: string) => {
  const i = argv.indexOf(`--${name}`);
  return i < 0 ? undefined : argv[i + 1];
};
const [projectArg] = argv.filter((a, i) => !a.startsWith("--") && !VALUE_FLAGS.has(argv[i - 1]) && !(argv[i - 1] === "--offline" && MODEL_MODES.includes(a)));
if (!projectArg) {
  console.error("usage: npx tsx scripts/action-demo.ts <project-dir> [--changed <file>[:<from>-<to>],...] [--fail-on <sev>] [--runs <n>] [--seed <comments.json>] [--offline [finding|garbage]] [--json]");
  process.exit(2);
}
const project = path.resolve(projectArg);
const asJson = argv.includes("--json");
const offline = argv.includes("--offline") ? (MODEL_MODES.find((m) => m === opt("offline")) ?? "finding") : undefined;
const log = (text: string) => (asJson ? process.stderr : process.stdout).write(`${text}\n`);

function sourceFiles(dir: string, rel = ""): string[] {
  return readdirSync(path.join(dir, rel)).flatMap((name) => {
    const r = path.posix.join(rel, name);
    if (name === "node_modules" || name.startsWith(".")) return [];
    return statSync(path.join(dir, r)).isDirectory() ? sourceFiles(dir, r) : [r];
  });
}

/** The simulated PR's files: each changed file as a patch adding its lines (all of them, or the given range). */
function pullFiles(): { filename: string; status: string; patch: string }[] {
  const specs = opt("changed")?.split(",").filter(Boolean) ?? sourceFiles(project);
  return specs.map((spec) => {
    const [filename, range] = spec.split(":");
    const lines = readFileSync(path.join(project, filename), "utf8").replace(/\n$/, "").split("\n");
    const [from, to] = range ? range.split("-").map(Number) : [1, lines.length];
    const added = lines.slice(from - 1, to);
    return { filename, status: range ? "modified" : "added", patch: [`@@ -${from},0 +${from},${added.length} @@`, ...added.map((l) => `+${l}`)].join("\n") };
  });
}

interface Recorded {
  reviewComments: { id: number; path: string; line?: number; subject_type?: string; body: string; edited?: boolean }[];
  issueComments: { id: number; body: string }[];
  rejected: { route: string; reason: string }[];
}

/** A stand-in for the GitHub REST endpoints the runner uses, rejecting comments GitHub would reject. */
function fakeGitHub(files: ReturnType<typeof pullFiles>, rec: Recorded): http.Server {
  let nextId = 1;
  const diff = new Map(files.map((f) => [f.filename, commentableLines(f.patch)]));
  const page = <T>(items: T[], url: URL) => {
    const per = Number(url.searchParams.get("per_page") ?? 30);
    const n = Number(url.searchParams.get("page") ?? 1);
    return items.slice((n - 1) * per, n * per);
  };
  return http.createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const url = new URL(req.url!, "http://x");
      const route = `${req.method} ${url.pathname.replace(`/repos/${REPO}`, "")}`;
      const send = (status: number, body: unknown) => {
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(body));
      };
      const reject = (reason: string) => {
        rec.rejected.push({ route, reason });
        send(422, { message: "Validation Failed", errors: [reason] });
      };
      if (req.headers.authorization !== "Bearer demo-token") return send(401, { message: "Bad credentials" });
      const body = raw ? JSON.parse(raw) : {};
      if (route === `GET /pulls/${PR}/files`) return send(200, page(files, url));
      if (route === `GET /pulls/${PR}/comments`) return send(200, page(rec.reviewComments, url));
      if (route === `GET /issues/${PR}/comments`) return send(200, page(rec.issueComments, url));
      if (route === `POST /pulls/${PR}/comments`) {
        if (body.commit_id !== HEAD_SHA) return reject("commit_id is not the PR head");
        if (!diff.has(body.path)) return reject(`path ${body.path} is not part of the pull request`);
        if (body.subject_type !== "file" && !diff.get(body.path)!.has(body.line)) return reject(`line ${body.line} of ${body.path} is not part of the diff`);
        const c = { id: nextId++, path: body.path, line: body.line, subject_type: body.subject_type, body: body.body };
        rec.reviewComments.push(c);
        return send(201, c);
      }
      if (route === `POST /issues/${PR}/comments`) {
        const c = { id: nextId++, body: body.body };
        rec.issueComments.push(c);
        return send(201, c);
      }
      const review = /^PATCH \/pulls\/comments\/(\d+)$/.exec(route);
      if (review) {
        const c = rec.reviewComments.find((x) => x.id === Number(review[1]));
        if (!c) return send(404, { message: "Not Found" });
        Object.assign(c, { body: body.body, edited: true });
        return send(200, c);
      }
      const edit = /^PATCH \/issues\/comments\/(\d+)$/.exec(route);
      if (edit) {
        const c = rec.issueComments.find((x) => x.id === Number(edit[1]));
        if (!c) return send(404, { message: "Not Found" });
        c.body = body.body;
        return send(200, c);
      }
      send(404, { message: `no stand-in for ${route}` });
    });
  });
}

/** A stand-in for the Meta Model API's Responses endpoint. */
function fakeModel(mode: string): http.Server {
  return http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const text =
        mode === "garbage"
          ? "I cannot answer that in JSON."
          : JSON.stringify([
              {
                type: "SQL Injection",
                cwe: "CWE-89",
                severity: "high",
                path: 1,
                explanation: "(canned offline reply) Request input is concatenated into the SQL text without parameterization.",
                suggestedPatch: "// (canned offline reply) pass the value as a bound parameter instead of concatenating it",
              },
            ]);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ id: "r", object: "response", status: "completed", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text, annotations: [] }] }] }));
    });
  });
}

const listen = (s: http.Server) => new Promise<string>((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));

async function main(): Promise<number> {
  if (!offline) process.loadEnvFile?.(".env");
  const files = pullFiles();
  const seeded = opt("seed") ? (JSON.parse(readFileSync(opt("seed")!, "utf8")) as { path: string; line?: number; body: string }[]) : [];
  const rec: Recorded = { reviewComments: seeded.map((c, i) => ({ id: 900 + i, ...c })), issueComments: [], rejected: [] };
  const github = fakeGitHub(files, rec);
  const model = offline ? fakeModel(offline) : undefined;
  const apiUrl = await listen(github);
  const modelUrl = model ? await listen(model) : undefined;
  const tmp = mkdtempSync(path.join(tmpdir(), "museflowcheck-action-"));
  // the "checkout": a copy outside this repository, so no settings file or .env of ours is picked up
  const workspace = path.join(tmp, "workspace");
  cpSync(project, workspace, { recursive: true });
  const event = path.join(tmp, "event.json");
  writeFileSync(event, JSON.stringify({ pull_request: { number: PR, head: { sha: HEAD_SHA } } }));

  const runner = fileURLToPath(new URL("../src/action/run.ts", import.meta.url));
  const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));
  const runs: { code: number | null; outputs: Record<string, string>; log: string; stepSummary: string }[] = [];
  try {
    for (let i = 0; i < Number(opt("runs") ?? 1); i++) {
      const output = path.join(tmp, `output-${i}`);
      const stepSummary = path.join(tmp, `summary-${i}.md`);
      writeFileSync(output, "");
      writeFileSync(stepSummary, "");
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_REPOSITORY: REPO,
        GITHUB_EVENT_NAME: "pull_request",
        GITHUB_EVENT_PATH: event,
        GITHUB_API_URL: apiUrl,
        GITHUB_SERVER_URL: "https://github.example",
        GITHUB_RUN_ID: String(1000 + i),
        GITHUB_OUTPUT: output,
        GITHUB_STEP_SUMMARY: stepSummary,
        INPUT_PATH: ".",
        INPUT_FAIL_ON: opt("fail-on") ?? "high",
        INPUT_GITHUB_TOKEN: "demo-token",
        ...(modelUrl ? { META_API_KEY: "offline-demo", META_BASE_URL: modelUrl, META_MODEL: "stand-in" } : {}),
      };
      log(`── run ${i + 1}: runner on ${path.relative(".", project) || "."} ──`);
      const child = spawn(tsx, [runner], { cwd: tmp, env, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => ((out += d), asJson || process.stdout.write(d)));
      child.stderr.on("data", (d) => ((out += d), asJson || process.stderr.write(d)));
      const code = await new Promise<number | null>((r) => child.on("close", r));
      const outputs = Object.fromEntries(readFileSync(output, "utf8").split("\n").filter(Boolean).map((l) => l.split("=", 2) as [string, string]));
      runs.push({ code, outputs, log: out, stepSummary: readFileSync(stepSummary, "utf8") });
      log(`exit ${code}  outputs ${JSON.stringify(outputs)}`);
    }
  } finally {
    github.close();
    model?.close();
    rmSync(tmp, { recursive: true, force: true });
  }

  if (asJson) {
    console.log(JSON.stringify({ runs, ...rec }, null, 2));
  } else {
    log(`\n══ ${rec.reviewComments.length} inline review comment(s) recorded ══`);
    for (const c of rec.reviewComments) log(`\n── ${c.path}${c.line ? `:${c.line}` : " (file-level)"}${c.edited ? " (edited)" : ""} ──\n${c.body}`);
    log(`\n══ summary comment (${rec.issueComments.length}) ══`);
    for (const c of rec.issueComments) log(c.body);
    for (const r of rec.rejected) log(`✗ rejected ${r.route}: ${r.reason}`);
  }
  return runs.at(-1)?.code ?? 1;
}

main().then((code) => process.exit(code));
