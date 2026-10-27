// Offline tests for model-response parsing (no API calls).
import assert from "node:assert/strict";
import { test } from "node:test";
import { extractJsonArray, FindingParseError, parseFindings } from "../src/engine/parse.js";

const finding = {
  type: "SQL Injection",
  cwe: "CWE-89",
  severity: "HIGH",
  file: "model-made-this-up.js",
  sourceLine: "L3",
  sinkLine: 7,
  taintPath: ["L3: const q = req.query.q", "L5: sql = base + q", 'L7: db.query(sql) // "]" ['],
  explanation: "e",
  suggestedPatch: "p",
  confidence: "confirmed",
};
const json = JSON.stringify([finding]);

test("bare array", () => assert.equal(extractJsonArray(json).length, 1));
test("empty array", () => assert.deepEqual(extractJsonArray("[]"), []));
test("fenced with prose", () => assert.equal(extractJsonArray(`Here:\n\`\`\`json\n${json}\n\`\`\`\nDone [1].`).length, 1));
test("fence without language tag", () => assert.equal(extractJsonArray(`\`\`\`\n${json}\n\`\`\``).length, 1));
test("prose with stray brackets before the array", () => assert.equal(extractJsonArray(`See [note] and [1]: ${json} ok`).length, 1));
test("BOM and zero-width characters", () => assert.equal(extractJsonArray(`﻿​${json}`).length, 1));
test("wrapped in an object", () => assert.equal(extractJsonArray(`{"findings": ${json}}`).length, 1));
test("empty array in prose", () => assert.deepEqual(extractJsonArray("No issues found: []"), []));

test("no JSON at all fails", () => assert.throws(() => extractJsonArray("No findings."), FindingParseError));
test("malformed array fails instead of returning an inner fragment", () => {
  const broken = '[{"type":"SQL Injection","taintPath":[],"cwe":"CWE-89",}]';
  assert.throws(() => extractJsonArray(broken), FindingParseError);
});

test("normalizes and overrides fields", () => {
  const [f] = parseFindings(json, "real/path.js", 10);
  assert.equal(f.file, "real/path.js");
  assert.equal(f.severity, "high");
  assert.equal(f.sourceLine, 3);
  assert.equal(f.confidence, "suspected");
  assert.equal(f.taintPath.length, 3);
});

test("rejects line numbers outside the file", () => {
  assert.throws(() => parseFindings(json, "x.js", 5), /sinkLine must be a line number between 1 and 5/);
});
test("rejects unknown severity", () => {
  assert.throws(() => parseFindings(JSON.stringify([{ ...finding, severity: "urgent" }]), "x.js", 10), FindingParseError);
});
test("rejects single-hop taint path", () => {
  assert.throws(() => parseFindings(JSON.stringify([{ ...finding, taintPath: ["L7: x"] }]), "x.js", 10), /taintPath/);
});
test("parse error keeps the raw response", () => {
  try {
    parseFindings("garbage", "x.js", 10);
    assert.fail("expected a throw");
  } catch (err) {
    assert.ok(err instanceof FindingParseError);
    assert.equal(err.raw, "garbage");
  }
});
