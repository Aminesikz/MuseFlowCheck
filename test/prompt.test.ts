// Offline guard: the prompt's fixed text must stay codebase-agnostic.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { buildSqliPrompt, numberLines } from "../src/engine/prompt.js";

const instructions = buildSqliPrompt("PLACEHOLDER", "").split("FILE: PLACEHOLDER")[0];

/** Library/framework names the prompt is meant to mention; they're conventional, not fixture-specific. */
const LIBRARY_NAMES = new Set(["express", "sequelize", "knex", "mysql", "sqlite3", "Database", "Sequelize", "QueryTypes"]);

/** Distinctive identifiers (paths, string literals, variable names) from every file we scan in testing. */
function identifiersFrom(dir: string): string[] {
  const ids = new Set<string>();
  for (const name of readdirSync(new URL(dir, import.meta.url)).filter((n) => /\.(js|ts)$/.test(n))) {
    ids.add(name);
    const code = readFileSync(new URL(`${dir}/${name}`, import.meta.url), "utf8");
    for (const m of code.matchAll(/['"`](\/[\w/:-]+)['"`]/g)) ids.add(m[1]); // route paths
    for (const m of code.matchAll(/(?:const|let|function)\s+(\w{6,})/g)) ids.add(m[1]); // longer local names
  }
  return [...ids].filter((id) => !LIBRARY_NAMES.has(id));
}

for (const dir of ["../fixtures", "../test-cases"]) {
  test(`prompt contains no identifiers from ${dir.slice(3)}/`, () => {
    for (const id of identifiersFrom(dir)) {
      assert.ok(!instructions.includes(id), `prompt mentions "${id}" from ${dir}`);
    }
  });
}

test("prompt defines the sink as the execute call", () => {
  assert.match(instructions, /sinkLine is the line of that EXECUTE call/);
  assert.match(instructions, /illustrative, NOT exhaustive/);
});

test("severity is an ordered decision where impact outranks reachability", () => {
  assert.match(instructions, /IN ORDER and assign the FIRST one that matches/);
  assert.match(instructions, /Requiring a login does NOT lower severity/);
  // The old contradictory clause must not come back.
  assert.doesNotMatch(instructions, /reachable only behind authentication/);
  const order = ['1. "critical"', '2. "high"', '3. "medium" or "low"'].map((s) => instructions.indexOf(s));
  assert.ok(order.every((i) => i >= 0) && order[0] < order[1] && order[1] < order[2]);
});

test("numberLines prefixes 1-based, padded line numbers", () => {
  assert.equal(numberLines("a\nb"), "1 | a\n2 | b");
});
