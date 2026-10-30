// Settings layering (flags > MUSEFLOWCHECK_* env > museflowcheck.config.json) and the human report: the color policy
// and the finding card. Presentation and configuration only — the data path is covered by the CLI tests.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { ConfigError, envVar, layeredValues, loadConfig, sourcedSettings } from "../src/config.js";
import { colorEnabled, findingCard, makeColors, patchFile, severityCounts } from "../src/report.js";
import type { Finding } from "../src/types/index.js";

const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-config-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function dirWith(name: string, config: unknown): string {
  const dir = path.join(tmp, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "museflowcheck.config.json"), typeof config === "string" ? config : JSON.stringify(config));
  return dir;
}

test("loadConfig reads the first file found, maps keys to flags, and skips comment keys", () => {
  const first = dirWith("first", { "//": "note", target: "http://localhost:4000", probeRange: 5, loginBody: { email: "a@b.test" } });
  const second = dirWith("second", { target: "http://localhost:9" });
  const cfg = loadConfig([path.join(tmp, "missing"), first, second]);
  assert.equal(cfg.file, path.join(first, "museflowcheck.config.json"));
  assert.deepEqual(Object.fromEntries(cfg.values), { target: "http://localhost:4000", "probe-range": "5", "login-body": '{"email":"a@b.test"}' });
  assert.deepEqual(loadConfig([path.join(tmp, "missing")]).values.size, 0);
});

test("loadConfig rejects invalid JSON, unknown keys and wrong types", () => {
  assert.throws(() => loadConfig([dirWith("bad-json", "{ target: ")]), ConfigError);
  assert.throws(() => loadConfig([dirWith("typo", { tagret: "x" })]), /unknown setting "tagret"/);
  assert.throws(() => loadConfig([dirWith("type", { token: ["x"] })]), /"token" must be a string/);
});

test("a command-line flag beats the environment, which beats the config file", () => {
  const config = new Map([["target", "http://from-config.test"], ["identity", "config identity"], ["mode", "xss"]]);
  const env = { [envVar("target")]: "http://from-env.test", [envVar("identity")]: "env identity" };
  const flags = new Map<string, string | true>([["target", "http://from-flag.test"], ["json", true]]);
  const value = layeredValues(flags, env, config);
  assert.equal(value("target"), "http://from-flag.test");
  assert.equal(value("identity"), "env identity");
  assert.equal(value("mode"), "xss");
  assert.equal(value("root"), undefined);
  assert.equal(envVar("probe-range"), "MUSEFLOWCHECK_PROBE_RANGE");
  // Only names are reported, never values.
  assert.deepEqual(sourcedSettings(flags, env, config), { env: ["identity"], config: ["mode"] });
});

test("a login path from a higher-precedence source replaces a token from a lower one", () => {
  const config = new Map([["token", "config-token"]]);
  assert.equal(layeredValues(new Map([["login-path", "/api/login"]]), {}, config)("token"), undefined);
  assert.equal(layeredValues(new Map(), {}, config)("token"), "config-token");
  // Both on the command line: the token still wins, as before.
  assert.equal(layeredValues(new Map([["token", "t"], ["login-path", "/l"]]), {}, new Map())("token"), "t");
});

test("color is off for --json, --no-color, NO_COLOR and pipes; FORCE_COLOR turns it on", () => {
  const base = { json: false, noColorFlag: false, env: {}, isTTY: true };
  assert.equal(colorEnabled(base), true);
  assert.equal(colorEnabled({ ...base, isTTY: false }), false);
  assert.equal(colorEnabled({ ...base, json: true, env: { FORCE_COLOR: "1" } }), false);
  assert.equal(colorEnabled({ ...base, noColorFlag: true }), false);
  assert.equal(colorEnabled({ ...base, env: { NO_COLOR: "1" } }), false);
  assert.equal(colorEnabled({ ...base, isTTY: false, env: { FORCE_COLOR: "1" } }), true);
});

const confirmed: Finding = {
  type: "SQL Injection",
  cwe: "CWE-89",
  severity: "critical",
  file: "routes/a.js",
  sourceLine: 11,
  sinkFile: "db/a.js",
  sinkLine: 14,
  taintPath: ["routes/a.js:11  const { id } = req.query;", "db/a.js:13  async function find(id)  [param id]", "db/a.js:14  pool.query(sql)"],
  explanation: "The id is concatenated into SQL text.",
  suggestedPatch: "function find(id) {\n  return pool.query('SELECT 1 WHERE id = $1', [id]);\n}\n",
  httpRoute: "GET /api/a",
  confidence: "confirmed",
  verification: { outcome: "confirmed", summary: "Exploit returned 4 rows vs the baseline's 2.", exploit: { method: "GET", path: "/api/a?id=0+OR+1%3D1", status: 200, responseExcerpt: "…" } },
};

test("a finding card shows every part — badges, location, path, why, proof and fix — as plain text without color", () => {
  const card = findingCard(makeColors(false), confirmed, 1, 3, 80);
  assert.doesNotMatch(card, /\x1b\[/);
  assert.match(card, /^1\/3 {2}\[CRITICAL\] {2}SQL Injection · CWE-89 +✓ exploit confirmed$/m);
  assert.equal(card.split("\n")[1].length, 80, "the verification badge is right-aligned to the width");
  assert.match(card, /^ {5}GET \/api\/a$/m);
  assert.match(card, /^ {5}routes\/a\.js:11 → db\/a\.js:14$/m);
  assert.match(card, /^ {4}1 {2}routes\/a\.js:11 {2}const \{ id \} = req\.query;$/m);
  assert.match(card, /^ {4}3 {2}db\/a\.js:14 {2}pool\.query\(sql\)$/m);
  assert.match(card, /^ {2}Why\n {4}The id is concatenated into SQL text\.$/m);
  assert.match(card, /^ {2}Proof\n {4}Exploit returned 4 rows vs the baseline's 2\.\n {4}exploit {2}GET \/api\/a\?id=0\+OR\+1%3D1 → 200$/m);
  assert.match(card, /^ {2}Fix — suggested patch for db\/a\.js\n {4}│ function find\(id\) \{\n {4}│ {3}return pool\.query/m);
  assert.doesNotMatch(card, /│ $/m, "no empty trailing patch line");

  const suspected = findingCard(makeColors(false), { ...confirmed, confidence: "suspected", verification: undefined }, 2, 3, 80);
  assert.match(suspected, /suspected$/m);
  assert.doesNotMatch(suspected, /Proof/);
});

test("with color the card and counts carry ANSI styling; the text is the same once styling is removed", () => {
  const plain = findingCard(makeColors(false), confirmed, 1, 1, 80);
  const colored = findingCard(makeColors(true), confirmed, 1, 1, 80);
  assert.match(colored, /\x1b\[/);
  assert.equal(colored.replace(/\x1b\[[0-9;]*m/g, ""), plain);
  assert.equal(severityCounts(makeColors(false), [confirmed]), "critical 1, high 0, medium 0, low 0");
});

test("the fix is labeled with the file the patch changes, not always the sink's", () => {
  // A patched function: the file of the hop that declares it.
  assert.equal(patchFile(confirmed), "db/a.js");
  // A patched route registration (an access check): the handler's file, where the input enters — not the sink.
  const access: Finding = { ...confirmed, cwe: "CWE-639", suggestedPatch: "router.get('/:id', async (req, res) => {\n});" };
  assert.equal(patchFile(access), "routes/a.js");
  assert.match(findingCard(makeColors(false), access, 1, 1, 80), /^ {2}Fix — suggested patch for routes\/a\.js$/m);
  // A patch whose function the path never declares: no file named rather than a guess.
  const unknown: Finding = { ...confirmed, suggestedPatch: "function elsewhere() {}" };
  assert.equal(patchFile(unknown), undefined);
  assert.match(findingCard(makeColors(false), unknown, 1, 1, 80), /^ {2}Fix — suggested patch$/m);
});
