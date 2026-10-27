// Patch proof (the second half of verification): re-run a confirmed PoC against a copy of the project with the
// finding's suggestedPatch applied, and check the exploit now fails while a benign request still works.
//
// The original project is never modified: everything happens in a throwaway copy that is removed afterwards.
// Patch application is deliberately conservative — it replaces a named function the patch redefines in the sink
// file. When the patch is not a clean single-function replacement (e.g. an inline route handler, or edits spanning
// several files), it reports "not-attempted" with the reason rather than guessing or faking a pass.
import { cpSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Project, SyntaxKind, type SourceFile } from "ts-morph";
import type { Finding, Verification } from "../../types/index.js";
import { evaluate } from "./evaluate.js";
import type { Check, PocRequest } from "./poc.js";
import { Target } from "./target.js";

export type PatchProof = NonNullable<Verification["patchProof"]>;

/** Starts a patched copy of the project and returns a Target for it plus a stop handle. Supplied by the CLI. */
export type StartPatched = (projectDir: string) => Promise<{ target: Target; stop: () => Promise<void> }>;

export interface PatchProverOptions {
  /** The target project directory (its files are copied, never edited). */
  projectDir: string;
  /** Path the finding's `file`/`sinkFile` are relative to (defaults to projectDir). */
  sourceRoot?: string;
  start: StartPatched;
}

const ok = (status: number) => status >= 200 && status < 300;

/** Top-level function names a patch snippet defines: `function f`, `const f = () =>`, `exports.f = function`. */
function patchedFunctionNames(patch: string): string[] {
  const project = new Project({ useInMemoryFileSystem: true, compilerOptions: { allowJs: true } });
  let sf: SourceFile;
  try {
    sf = project.createSourceFile("patch.ts", patch);
  } catch {
    return [];
  }
  const names = new Set<string>();
  for (const fn of sf.getFunctions()) if (fn.getName()) names.add(fn.getName()!);
  for (const decl of sf.getVariableDeclarations()) {
    const init = decl.getInitializer();
    if (init && (init.getKind() === SyntaxKind.ArrowFunction || init.getKind() === SyntaxKind.FunctionExpression)) names.add(decl.getName());
  }
  for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const left = bin.getLeft().getText();
    const m = /^(?:module\.)?exports\.(\w+)$/.exec(left);
    if (m) names.add(m[1]);
  }
  return [...names];
}

/** Replaces, in `file`, each top-level function the patch redefines by name. Returns the names replaced. */
function applyNamedFunctions(file: SourceFile, patch: string, names: string[]): string[] {
  const applied: string[] = [];
  const patchProject = new Project({ useInMemoryFileSystem: true, compilerOptions: { allowJs: true } });
  const patchSf = patchProject.createSourceFile("patch.ts", patch);
  for (const name of names) {
    const replacement = patchSf.getFunction(name) ?? patchSf.getVariableStatement((v) => v.getDeclarations().some((d) => d.getName() === name));
    const target = file.getFunction(name) ?? file.getVariableStatement((v) => v.getDeclarations().some((d) => d.getName() === name));
    if (!replacement || !target) continue;
    target.replaceWithText(replacement.getText());
    applied.push(name);
  }
  return applied;
}

/**
 * Applies `finding.suggestedPatch` to the copied project in `dir`. Returns the reason it could not be applied,
 * or undefined on success. Only clean single-file named-function replacements are applied.
 */
function applyPatch(dir: string, sourceRoot: string, finding: Finding): string | undefined {
  const names = patchedFunctionNames(finding.suggestedPatch);
  if (names.length === 0) {
    return "the suggested patch is not a named-function replacement (e.g. an inline route handler); apply it by hand to patch-prove this one";
  }
  const rel = finding.sinkFile ?? finding.file;
  const abs = path.join(dir, path.relative(sourceRoot, path.join(sourceRoot, rel)));
  const project = new Project({ compilerOptions: { allowJs: true }, skipAddingFilesFromTsConfig: true });
  let file: SourceFile;
  try {
    file = project.addSourceFileAtPath(abs);
  } catch {
    return `could not open ${rel} in the project copy`;
  }
  const applied = applyNamedFunctions(file, finding.suggestedPatch, names);
  if (applied.length === 0) return `none of the patched function(s) [${names.join(", ")}] were found in ${rel}`;
  file.saveSync();
  const missed = names.filter((n) => !applied.includes(n));
  if (missed.length > 0) return `the patch also changes [${missed.join(", ")}], which are not in ${rel}; apply it by hand to patch-prove this one`;
  return undefined;
}

/** Builds the patchProof function passed to verifyFinding, bound to one project and a way to run patched copies. */
export function verifyPatch(opts: PatchProverOptions): PatchProver {
  const sourceRoot = opts.sourceRoot ?? opts.projectDir;
  return async (finding, poc) => {
    const copy = mkdtempSync(path.join(tmpdir(), "flowcheck-patch-"));
    try {
      // Copy the project but share its dependencies, so the copy is cheap and the original is untouched.
      cpSync(opts.projectDir, copy, { recursive: true, filter: (src) => path.basename(src) !== "node_modules" });
      try {
        symlinkSync(path.join(opts.projectDir, "node_modules"), path.join(copy, "node_modules"), "dir");
      } catch {
        /* no node_modules to share; the copy already has whatever was not excluded */
      }

      const reason = applyPatch(copy, sourceRoot, finding);
      if (reason) return { outcome: "not-attempted", summary: reason };

      const { target, stop } = await opts.start(copy);
      try {
        const baseline = await run(target, poc.baseline);
        const exploit = await run(target, poc.exploit);
        const stillWorks = evaluate(poc.check, baseline, exploit).success;
        if (stillWorks) return { outcome: "still-exploitable", summary: `after applying the patch the exploit still succeeded (exploit status ${exploit.status})` };
        if (!ok(baseline.status)) return { outcome: "still-exploitable", summary: `the exploit was blocked, but the patched route no longer serves a benign request (baseline status ${baseline.status}) — the patch broke the route` };
        return { outcome: "blocked", summary: `patch verified: the exploit was blocked (exploit status ${exploit.status}) while a benign request still succeeded (baseline status ${baseline.status})` };
      } finally {
        await stop();
      }
    } catch (err) {
      return { outcome: "not-attempted", summary: `patch proof could not run: ${(err as Error).message}` };
    } finally {
      rmSync(copy, { recursive: true, force: true });
    }
  };
}

export type PatchProver = NonNullable<import("./index.js").VerifyDeps["patchProof"]>;

function run(target: Target, req: PocRequest) {
  return target.request(req.method, req.path, { query: req.query, body: req.body, authenticated: req.authenticated });
}

export type { Check };
