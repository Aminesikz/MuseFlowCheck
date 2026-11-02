// Offline check that a suggested patch closes every vector of a finding: apply the patch to a throwaway copy of the
// scanned tree, re-run the finding's own Stage 1 there, and see which of its inputs still reach the sink
// unneutralized. No model call and no server — the tracers run as they are. Not part of a scan: verification still
// confirms a finding with one exploit, and its patch proof replays that one exploit; this answers the other question,
// whether the fix left a sibling input open.
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Project, type Node, type SourceFile } from "ts-morph";
import { patchFile } from "../report.js";
import type { Finding, Vector } from "../types/index.js";
import { assembleAccessContext, routeLabel, type Access, type Guard } from "./access/index.js";
import { traceProject, type Hop } from "./crossfile/index.js";
import { applyNamedFunctions, patchedFunctionNames } from "./verify/patch.js";
import { inputOfOrigin } from "./vectors.js";
import { traceXssProject } from "./xss/index.js";

export interface VectorStatus {
  input: string;
  /** True when the input still reaches the sink unneutralized after the patch. */
  open: boolean;
}

export type PatchCheck = { applied: true; file: string; vectors: VectorStatus[] } | { applied: false; reason: string };

const REGISTRATION = /^(?:router|app)\.(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]*)\2/;

/** The route registration statement in `file` with the same method and path as the patch's, if any. */
function registrationIn(file: SourceFile, method: string, route: string): Node | undefined {
  return file.getStatements().find((s) => {
    const m = REGISTRATION.exec(s.getText());
    return m !== null && m[1] === method && m[3] === route;
  });
}

/**
 * Applies the patch to `abs` (a file of the copy): a route registration it contains replaces the one with the same
 * method and path, and anything else it adds (a helper, an import) goes at the top; otherwise the named functions it
 * redefines replace theirs. A reason when it cannot be applied.
 */
function applyTo(abs: string, patch: string): string | undefined {
  const project = new Project({ compilerOptions: { allowJs: true }, skipAddingFilesFromTsConfig: true });
  const file = project.addSourceFileAtPath(abs);
  const statements = new Project({ useInMemoryFileSystem: true, compilerOptions: { allowJs: true } }).createSourceFile("patch.ts", patch).getStatements();
  const replacement = statements.find((s) => REGISTRATION.test(s.getText()));
  if (replacement) {
    const [, method, , route] = REGISTRATION.exec(replacement.getText())!;
    const target = registrationIn(file, method, route);
    if (!target) return `no ${method.toUpperCase()} '${route}' registration to replace`;
    target.replaceWithText(replacement.getText());
    const extra = statements.filter((s) => s !== replacement).map((s) => s.getText());
    if (extra.length > 0) file.insertStatements(0, extra.join("\n"));
  } else {
    const names = patchedFunctionNames(patch);
    if (names.length === 0) return "the patch is neither a route registration nor a named function";
    const applied = applyNamedFunctions(file, patch, names);
    if (applied.length !== names.length) return `the patch's function(s) [${names.join(", ")}] are not all in this file`;
  }
  file.saveSync();
  return undefined;
}

/** The finding's inputs to check: its vectors, or for a single-input finding its one source (input unnamed). */
function inputsOf(f: Finding): (Pick<Vector, "file" | "httpRoute"> & { input?: string })[] {
  return f.vectors ?? [{ file: f.file, ...(f.httpRoute ? { httpRoute: f.httpRoute } : {}) }];
}

/** Whether a traced path from `source` (file, input, route) into `sinkFile` is still there. */
function matches(v: ReturnType<typeof inputsOf>[number], sourceFile: string, input: string, route: string | undefined, sinkFile: string, findingSink: string): boolean {
  return sourceFile === v.file && (v.input === undefined || input === v.input) && (!v.httpRoute || !route || route === v.httpRoute) && sinkFile === findingSink;
}

/** The variable a hop leaves the value in: a parameter (`[param x]`), a declaration, or an assignment target. */
function heldIn(hop: Hop): string | undefined {
  const code = hop.code.trim();
  return /\[param ([A-Za-z_$][\w$]*)/.exec(code)?.[1] ?? declared(code) ?? /^([A-Za-z_$][\w$]*)\s*(?:\+=|=(?!=))/.exec(code)?.[1];
}

/**
 * Whether a traced path passes the value on only as its `.length` at some hop — e.g. a placeholder number built from a
 * bound-values array (`' AND status = $' + params.length`). A length is a number, not the input's text, so such a path
 * no longer carries the input into the SQL or HTML. Stage 1 over-approximates there; detection keeps that, and only
 * this check reads it. A hop whose variable cannot be told is never treated as cut.
 */
export function onlyLengthAt(hops: Hop[]): boolean {
  for (let i = 1; i < hops.length; i++) {
    const name = heldIn(hops[i - 1]);
    if (!name) continue;
    const uses = [...hops[i].code.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, "\\$")}(?![\\w$])(\\??\\.length\\b)?`, "g"))];
    if (uses.length > 0 && uses.every((m) => m[1] !== undefined)) return true;
  }
  return false;
}

function statusAfterPatch(copy: string, f: Finding): VectorStatus[] {
  const sinkFile = f.sinkFile ?? f.file;
  const inputs = inputsOf(f);
  const label = (v: ReturnType<typeof inputsOf>[number]) => v.input ?? `${v.file} input`;
  if (f.cwe === "CWE-89" || /sql/i.test(f.type)) {
    const open = traceProject(copy).paths.filter((p) => p.sqlText && !onlyLengthAt(p.hops));
    return inputs.map((v) => ({ input: label(v), open: open.some((p) => matches(v, p.hops[0].file, inputOfOrigin(p.origin), p.route, p.hops.at(-1)!.file, sinkFile)) }));
  }
  if (f.cwe === "CWE-79" || /cross-site/i.test(f.type)) {
    const open = traceXssProject(copy).xss.filter((p) => !p.encoded && !onlyLengthAt(p.hops));
    return inputs.map((v) => ({ input: label(v), open: open.some((p) => matches(v, p.hops[0].file, p.stored ?? inputOfOrigin(p.origin), p.route, p.hops.at(-1)!.file, sinkFile)) }));
  }
  // Access control: Stage 1 counts one owner check in a handler as covering all of its reads, so here an identifier is
  // closed only by a check that uses it — the identifier itself or a record the route loaded by it — or by a query
  // constrained by the caller's identity at its own statement. A stricter reading than detection's, for this check only.
  const route = assembleAccessContext(copy).routes.find((r) => routeLabel(r) === f.httpRoute);
  if (!route) return inputs.map((v) => ({ input: label(v), open: true }));
  const key = (a: Access) => `${a.location}.${a.field}`;
  return inputs.map((v) => {
    const accesses = route.accesses.filter((a) => v.input === undefined || key(a) === v.input);
    const names = (a: Access) => [a.field, ...route.accesses.filter((o) => key(o) === key(a)).map(recordOf)].filter((n): n is string => !!n);
    return { input: label(v), open: accesses.some((a) => !route.guards.some((g) => checks(g, a, names(a)))) };
  });
}

const declared = (code: string) => /^(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/.exec(code.trim())?.[1];
const mentions = (code: string, name: string) => new RegExp(`(?<![\\w$])${name.replace(/\$/g, "\\$")}(?![\\w$])`).test(code);

/** The variable an access's result is assigned to (`const record = await load(req.params.id)`), if any. */
function recordOf(a: Access): string | undefined {
  const source = a.path.hops.find((h) => h.kind === "source");
  return source && declared(source.code);
}

/** Whether `g` checks this access: a query constrained at its statement, or a comparison using one of `names`. */
function checks(g: Guard, a: Access, names: string[]): boolean {
  const sink = a.path.hops.at(-1)!;
  if (g.kind === "query constrained by identity") return g.file === sink.file && g.line === sink.line;
  return names.some((n) => mentions(g.code, n));
}

/**
 * Applies `finding.suggestedPatch` to a copy of `root` (the scanned directory its paths are relative to) and re-runs
 * Stage 1 for the finding's class; reports, per input, whether it still reaches the sink. The original is not touched.
 */
export function checkPatchVectors(root: string, finding: Finding): PatchCheck {
  const target = patchFile(finding) ?? finding.sinkFile ?? finding.file;
  const copy = mkdtempSync(path.join(tmpdir(), "flowcheck-vectors-"));
  try {
    cpSync(root, copy, { recursive: true, filter: (src) => path.basename(src) !== "node_modules" });
    let reason: string | undefined;
    try {
      reason = applyTo(path.join(copy, target), finding.suggestedPatch);
    } catch (err) {
      reason = `could not apply the patch to ${target}: ${(err as Error).message}`;
    }
    if (reason) return { applied: false, reason };
    return { applied: true, file: target, vectors: statusAfterPatch(copy, finding) };
  } finally {
    rmSync(copy, { recursive: true, force: true });
  }
}
