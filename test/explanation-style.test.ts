// Explanation wording: every judge prompt asks for an explanation written as finished prose for a developer — no
// prompt labels ("Path 1"), no first person, no reach labels copied as fragments. Wording only: the block sits after
// the rules, and the output schema each judge parses is unchanged. Offline: prompts are built from the fixtures.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { assembleAccessContext, buildAccessPrompt, candidates } from "../src/engine/access/index.js";
import { buildJudgePrompt, groupBySink, traceProject } from "../src/engine/crossfile/index.js";
import { buildSqliPrompt, EXPLANATION_STYLE } from "../src/engine/prompt.js";
import { buildXssPrompt, groupXssBySink, traceXssProject } from "../src/engine/xss/index.js";

const fixture = (name: string) => fileURLToPath(new URL(`./${name}`, import.meta.url));

const sqli = traceProject(fixture("crossfile-project"));
const access = assembleAccessContext(fixture("access-project"));
const xss = traceXssProject(fixture("xss-project"));
const prompts: Record<string, string> = {
  "single-file SQL injection": buildSqliPrompt("PLACEHOLDER", ""),
  "cross-file SQL injection": buildJudgePrompt(groupBySink(sqli.paths.filter((p) => p.sqlText))[0]),
  "access control": buildAccessPrompt(access, candidates(access)[0]),
  XSS: buildXssPrompt(groupXssBySink(xss.xss)[0]),
};

/** The judges' output object: each field's name, in order (the single-file prompt states it as a TypeScript interface). */
const JUDGE_FIELDS = ["type", "cwe", "severity", "path", "explanation", "suggestedPatch"];
const SINGLE_FILE_FIELDS = ["type", "cwe", "severity", "file", "sourceLine", "sinkLine", "taintPath", "explanation", "suggestedPatch", "confidence"];

test("every judge prompt carries the explanation style once, after the rules and before the output schema", () => {
  for (const [name, prompt] of Object.entries(prompts)) {
    assert.equal(prompt.split(EXPLANATION_STYLE).length - 1, 1, `${name}: exactly once`);
    const at = prompt.indexOf(EXPLANATION_STYLE);
    assert.ok(at > prompt.lastIndexOf("SEVERITY"), `${name}: after the severity rules`);
    assert.ok(at < prompt.indexOf("\nOUTPUT\n"), `${name}: before OUTPUT`);
  }
});

test("the style forbids the observed leaks: prompt labels, first person, and reach labels as fragments", () => {
  assert.match(EXPLANATION_STYLE, /no "Path 1", "candidate path", "hop 3", rule numbers, or headings such as VIEWER REACH, ACTOR REACH or PATCH SCOPE/);
  assert.match(EXPLANATION_STYLE, /No first person \("I", "we", "I assume", "I think"\)/);
  assert.match(EXPLANATION_STYLE, /never as a label copied from these instructions/);
  assert.match(EXPLANATION_STYLE, /Complete sentences only: no fragments, dangling dashes, placeholders/);
  // And says it changes nothing else.
  assert.match(EXPLANATION_STYLE, /Whether to report, the severity, the path number and the patch follow the rules above, unchanged\.$/);
});

test("the explanation specs no longer invite labels: no 'paths into', '(A)/(B)/(C)', 'hop by hop' or 'state the viewer reach'", () => {
  for (const [name, prompt] of Object.entries(prompts)) {
    const spec = /"?explanation"?: string[;,]?\s*\/\/ ([^\n]*)/.exec(prompt)![1];
    assert.doesNotMatch(spec, /exploitable paths|\([ABC]\)|hop by hop|state the viewer reach|Path N/, name);
  }
});

test("the output schema each judge parses is unchanged", () => {
  const fields = (prompt: string) => [...prompt.slice(prompt.indexOf("\nOUTPUT\n")).matchAll(/^[ \t]+"?(\w+)"?\??: /gm)].map((m) => m[1]);
  assert.deepEqual(fields(prompts["single-file SQL injection"]), SINGLE_FILE_FIELDS);
  for (const name of ["cross-file SQL injection", "access control", "XSS"]) assert.deepEqual(fields(prompts[name]), JUDGE_FIELDS, name);
});
