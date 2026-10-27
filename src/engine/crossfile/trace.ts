// Stage 1 of cross-file analysis: a deterministic (no LLM) call-graph taint tracer built on ts-morph.
// Spike scope: tainted values passed directly as call arguments across require()/import boundaries.
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import {
  Node,
  Project,
  SyntaxKind,
  type ArrowFunction,
  type BinaryExpression,
  type CallExpression,
  type FunctionDeclaration,
  type FunctionExpression,
  type SourceFile,
  type VariableDeclaration,
} from "ts-morph";

export type HopKind = "source" | "propagate" | "build" | "call" | "param" | "sink";

/** A function on a traced path, with its source text for the Stage 2 code slice. */
export interface FunctionRef {
  file: string; // relative to the trace root
  name: string;
  startLine: number;
  endLine: number;
  code: string;
}

export interface Hop {
  file: string; // relative to the trace root
  line: number;
  code: string;
  kind: HopKind;
  fn: FunctionRef;
}

export interface CandidatePath {
  /** Ordered source → … → sink. */
  hops: Hop[];
  /** True when taint reaches the SQL text argument; false when it only reaches bound parameters. */
  sqlText: boolean;
}

/** A call into a project module that the tracer could not follow — the place a trace breaks. */
export interface UnresolvedCall {
  file: string;
  line: number;
  call: string;
  reason: string;
}

export interface TraceResult {
  root: string;
  entry: string;
  /** Number of request-handler functions found in the entry file. */
  handlers: number;
  paths: CandidatePath[];
  unresolved: UnresolvedCall[];
}

type Fn = FunctionDeclaration | ArrowFunction | FunctionExpression;
interface Taint {
  origin: string;
  hops: Hop[];
}
type Env = Map<string, Taint[]>;
type Binding = { kind: "namespace"; spec: string } | { kind: "named"; spec: string; imported: string };
type Callee = { kind: "function"; fn: Fn } | { kind: "sink" } | { kind: "external" } | { kind: "unresolved"; reason: string };

/** Request properties that carry attacker-controlled input. */
const SOURCE_PROPS = new Set(["query", "params", "body"]);
/** Methods that execute SQL when called on something that isn't a project function (pool.query, client.query, db.query, …). */
const SINK_METHODS = new Set(["query", "execute"]);
const MODULE_EXTENSIONS = ["", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts"];
const MAX_DEPTH = 8;

function isFn(node: Node): node is Fn {
  return Node.isFunctionDeclaration(node) || Node.isArrowFunction(node) || Node.isFunctionExpression(node);
}

function excerpt(node: Node, max = 140): string {
  const text = node.getText().replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function mergeTaints(a: Taint[], b: Taint[]): Taint[] {
  const out = [...a];
  for (const t of b) if (!out.some((o) => o.origin === t.origin)) out.push(t);
  return out;
}

/** Nearest ancestor directory containing package.json, else the entry's own directory. */
export function findProjectRoot(entry: string): string {
  let dir = path.dirname(path.resolve(entry));
  while (true) {
    if (existsSync(path.join(dir, "package.json"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return path.dirname(path.resolve(entry));
    dir = parent;
  }
}

class Tracer {
  private readonly project = new Project({
    compilerOptions: { allowJs: true },
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
  });
  private readonly bindingsCache = new Map<SourceFile, Map<string, Binding>>();
  private readonly onStack = new Set<Fn>();
  private readonly pathKeys = new Set<string>();
  readonly paths: CandidatePath[] = [];
  readonly unresolved: UnresolvedCall[] = [];

  constructor(readonly root: string) {}

  load(file: string): SourceFile {
    return this.project.getSourceFile(file) ?? this.project.addSourceFileAtPath(file);
  }

  /** Request handlers in a file: functions whose first parameter is read as `<param>.query|params|body`. */
  handlers(sf: SourceFile): { fn: Fn; req: string }[] {
    const found: { fn: Fn; req: string }[] = [];
    for (const node of sf.getDescendants()) {
      if (!isFn(node)) continue;
      const first = node.getParameters()[0]?.getNameNode();
      if (!first || !Node.isIdentifier(first)) continue;
      const req = first.getText();
      if (this.sourceAccesses(node, req).length > 0) found.push({ fn: node, req });
    }
    return found;
  }

  // ---- naming / hops ----------------------------------------------------------------------

  private rel(sf: SourceFile): string {
    return path.relative(this.root, sf.getFilePath()) || sf.getBaseName();
  }

  private fnName(fn: Fn): string {
    if (Node.isFunctionDeclaration(fn) && fn.getName()) return fn.getName()!;
    const parent = fn.getParent();
    if (Node.isVariableDeclaration(parent)) return parent.getName();
    if (Node.isBinaryExpression(parent)) return parent.getLeft().getText(); // exports.name = function …
    if (Node.isCallExpression(parent)) {
      const route = parent.getArguments()[0];
      const label = route && Node.isStringLiteral(route) ? ` '${route.getLiteralValue()}'` : "";
      return `${excerpt(parent.getExpression(), 40)}${label} handler`;
    }
    return "<anonymous>";
  }

  private fnRef(fn: Fn): FunctionRef {
    const sf = fn.getSourceFile();
    const startLine = fn.getStartLineNumber();
    const endLine = fn.getEndLineNumber();
    // Slice from the start of the enclosing statement's line so the snippet shows `router.get(...` / `async function`.
    const lines = sf.getFullText().split(/\r?\n/).slice(startLine - 1, endLine);
    return { file: this.rel(sf), name: this.fnName(fn), startLine, endLine, code: lines.join("\n") };
  }

  private hop(node: Node, kind: HopKind, fn: FunctionRef, code = excerpt(node)): Hop {
    return { file: this.rel(node.getSourceFile()), line: node.getStartLineNumber(), code, kind, fn };
  }

  /** The trimmed source line a node starts on. */
  private lineText(node: Node): string {
    return node.getSourceFile().getFullText().split(/\r?\n/)[node.getStartLineNumber() - 1].trim();
  }

  private signature(fn: Fn): string {
    const body = fn.getBody();
    const head = body ? fn.getText().slice(0, body.getStart() - fn.getStart()) : fn.getText();
    const sig = head.replace(/\s+/g, " ").replace(/\s*(=>)?\s*$/, "").trim();
    return Node.isFunctionDeclaration(fn) ? sig : `${this.fnName(fn)} = ${sig}`;
  }

  // ---- taint queries ----------------------------------------------------------------------

  /** `<req>.query`, `<req>.params`, `<req>.body` accesses within a node. */
  private sourceAccesses(node: Node, req: string | undefined): Node[] {
    if (!req) return [];
    const all = Node.isPropertyAccessExpression(node) ? [node] : [];
    all.push(...node.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression));
    return all.filter((pa) => {
      const target = pa.getExpression();
      return Node.isIdentifier(target) && target.getText() === req && SOURCE_PROPS.has(pa.getName());
    });
  }

  /** Taints carried by variables referenced in `expr` (property names and object keys are not references). */
  private idTaints(expr: Node, env: Env): Taint[] {
    const ids = Node.isIdentifier(expr) ? [expr] : expr.getDescendantsOfKind(SyntaxKind.Identifier);
    let out: Taint[] = [];
    for (const id of ids) {
      const parent = id.getParent();
      if (Node.isPropertyAccessExpression(parent) && parent.getNameNode() === id) continue;
      if (Node.isPropertyAssignment(parent) && parent.getNameNode() === id) continue;
      const taints = env.get(id.getText());
      if (taints) out = mergeTaints(out, taints);
    }
    return out;
  }

  /** New taints for request inputs read directly inside `expr` (e.g. a call argument `req.params.id`). */
  private inlineSourceTaints(expr: Node, req: string | undefined, ref: FunctionRef): Taint[] {
    return this.sourceAccesses(expr, req).map((pa) => ({
      origin: `${this.rel(pa.getSourceFile())}:${pa.getStartLineNumber()}:${pa.getText()}`,
      hops: [this.hop(pa, "source", ref, this.lineText(pa))],
    }));
  }

  private isStringBuild(expr: Node): boolean {
    const inner = Node.isAwaitExpression(expr) ? expr.getExpression() : expr;
    return (
      Node.isTemplateExpression(inner) ||
      (Node.isBinaryExpression(inner) && inner.getOperatorToken().getKind() === SyntaxKind.PlusToken)
    );
  }

  // ---- intraprocedural walk ---------------------------------------------------------------

  analyze(fn: Fn, env: Env, depth: number, req?: string): void {
    const body = fn.getBody();
    if (!body || depth > MAX_DEPTH || this.onStack.has(fn)) return;
    this.onStack.add(fn);
    const ref = this.fnRef(fn);

    body.forEachDescendant((node, traversal) => {
      if (isFn(node)) return traversal.skip(); // nested callbacks are out of spike scope
      if (Node.isVariableDeclaration(node)) this.onDeclaration(node, env, ref, req);
      else if (Node.isBinaryExpression(node)) this.onAssignment(node, env, ref, req);
      else if (Node.isCallExpression(node)) this.onCall(node, env, ref, depth, req);
    });

    this.onStack.delete(fn);
  }

  private onDeclaration(decl: VariableDeclaration, env: Env, ref: FunctionRef, req?: string): void {
    const init = decl.getInitializer();
    if (!init) return;
    const nameNode = decl.getNameNode();
    const names = Node.isIdentifier(nameNode)
      ? [nameNode.getText()]
      : nameNode.getDescendantsOfKind(SyntaxKind.BindingElement).map((b) => b.getName());

    const stmt = decl.getFirstAncestorByKind(SyntaxKind.VariableStatement) ?? decl;
    const readsSource = this.sourceAccesses(init, req).length > 0;
    const flowing = this.idTaints(init, env);
    const kind = this.isStringBuild(init) ? "build" : "propagate";

    for (const name of names) {
      let taints: Taint[] = [];
      if (readsSource) {
        taints.push({ origin: `${ref.file}:${decl.getStartLineNumber()}:${name}`, hops: [this.hop(stmt, "source", ref)] });
      }
      taints = mergeTaints(taints, flowing.map((t) => ({ origin: t.origin, hops: [...t.hops, this.hop(stmt, kind, ref)] })));
      if (taints.length > 0) env.set(name, taints);
      else env.delete(name);
    }
  }

  private onAssignment(bin: BinaryExpression, env: Env, ref: FunctionRef, req?: string): void {
    const op = bin.getOperatorToken().getKind();
    const left = bin.getLeft();
    if ((op !== SyntaxKind.EqualsToken && op !== SyntaxKind.PlusEqualsToken) || !Node.isIdentifier(left)) return;

    const right = bin.getRight();
    const kind = op === SyntaxKind.PlusEqualsToken || this.isStringBuild(right) ? "build" : "propagate";
    const incoming = mergeTaints(this.inlineSourceTaints(right, req, ref), this.idTaints(right, env)).map((t) => ({
      origin: t.origin,
      hops: [...t.hops, this.hop(bin, kind, ref)],
    }));

    const name = left.getText();
    const next = op === SyntaxKind.PlusEqualsToken ? mergeTaints(env.get(name) ?? [], incoming) : incoming;
    if (next.length > 0) env.set(name, next);
    else env.delete(name);
  }

  private onCall(call: CallExpression, env: Env, ref: FunctionRef, depth: number, req?: string): void {
    const argTaints = call
      .getArguments()
      .map((arg) => mergeTaints(this.inlineSourceTaints(arg, req, ref), this.idTaints(arg, env)));
    if (argTaints.every((t) => t.length === 0)) return;

    const callee = this.resolveCallee(call);
    if (callee.kind === "unresolved") {
      this.unresolved.push({ file: ref.file, line: call.getStartLineNumber(), call: excerpt(call.getExpression()), reason: callee.reason });
    } else if (callee.kind === "sink") {
      this.recordSink(call, argTaints, ref);
    } else if (callee.kind === "function") {
      this.enterCallee(call, callee.fn, argTaints, ref, depth);
    }
  }

  // ---- interprocedural: argument → parameter ------------------------------------------------

  private enterCallee(call: CallExpression, fn: Fn, argTaints: Taint[][], ref: FunctionRef, depth: number): void {
    const calleeRef = this.fnRef(fn);
    const callHop = this.hop(call, "call", ref);
    const paramHop: Hop = { file: calleeRef.file, line: fn.getStartLineNumber(), code: this.signature(fn), kind: "param", fn: calleeRef };
    const calleeEnv: Env = new Map();

    fn.getParameters().forEach((param, i) => {
      const taints = argTaints[i];
      if (!taints?.length) return;
      const nameNode = param.getNameNode();
      if (!Node.isIdentifier(nameNode)) {
        this.unresolved.push({
          file: calleeRef.file,
          line: param.getStartLineNumber(),
          call: excerpt(param),
          reason: "destructured parameter — argument→parameter mapping not supported in this spike",
        });
        return;
      }
      calleeEnv.set(
        nameNode.getText(),
        taints.map((t) => ({ origin: t.origin, hops: [...t.hops, callHop, { ...paramHop, code: `${paramHop.code}  [param ${nameNode.getText()}]` }] })),
      );
    });

    if (calleeEnv.size > 0) this.analyze(fn, calleeEnv, depth + 1);
  }

  private recordSink(call: CallExpression, argTaints: Taint[][], ref: FunctionRef): void {
    const sinkHop = this.hop(call, "sink", ref);
    const sqlText = argTaints[0]?.length > 0;
    const taints = sqlText ? argTaints[0] : argTaints.slice(1).flat();
    for (const t of taints) {
      const key = `${t.origin}->${sinkHop.file}:${sinkHop.line}`;
      if (this.pathKeys.has(key)) continue;
      this.pathKeys.add(key);
      this.paths.push({ hops: [...t.hops, sinkHop], sqlText });
    }
  }

  // ---- call resolution ----------------------------------------------------------------------

  private resolveCallee(call: CallExpression): Callee {
    const expr = call.getExpression();
    const sf = call.getSourceFile();
    const bindings = this.bindings(sf);

    if (Node.isIdentifier(expr)) {
      const name = expr.getText();
      const local = this.findFunction(sf, name);
      if (local) return { kind: "function", fn: local };
      const binding = bindings.get(name);
      if (binding?.kind === "named") return this.resolveExport(sf, binding.spec, binding.imported);
      return { kind: "external" };
    }

    if (Node.isPropertyAccessExpression(expr)) {
      const target = expr.getExpression();
      const method = expr.getName();
      const binding = Node.isIdentifier(target) ? bindings.get(target.getText()) : undefined;
      if (binding?.kind === "namespace") {
        const resolved = this.resolveExport(sf, binding.spec, method);
        if (resolved.kind !== "external") return resolved;
      }
      if (SINK_METHODS.has(method)) return { kind: "sink" };
    }
    return { kind: "external" };
  }

  private resolveExport(from: SourceFile, spec: string, name: string): Callee {
    if (!spec.startsWith(".")) return { kind: "external" };
    const target = this.resolveModule(from, spec);
    if (!target) return { kind: "unresolved", reason: `cannot resolve module '${spec}' from ${this.rel(from)}` };
    const fn = this.findExport(target, name);
    if (!fn) return { kind: "unresolved", reason: `module '${spec}' resolved to ${this.rel(target)}, but no exported function '${name}' was found` };
    return { kind: "function", fn };
  }

  private resolveModule(from: SourceFile, spec: string): SourceFile | undefined {
    const base = path.resolve(path.dirname(from.getFilePath()), spec);
    const bases = spec.endsWith(".js") ? [base, base.replace(/\.js$/, ".ts")] : [base];
    for (const b of bases) {
      for (const ext of MODULE_EXTENSIONS) {
        const candidate = b + ext;
        if (existsSync(candidate) && statSync(candidate).isFile()) return this.load(candidate);
      }
    }
    return undefined;
  }

  /** Local names bound by `require(...)` / `import` statements at the top level of a file. */
  private bindings(sf: SourceFile): Map<string, Binding> {
    const cached = this.bindingsCache.get(sf);
    if (cached) return cached;
    const map = new Map<string, Binding>();

    for (const decl of sf.getVariableDeclarations()) {
      let init = decl.getInitializer();
      let member: string | undefined;
      if (init && Node.isPropertyAccessExpression(init)) {
        member = init.getName(); // const fn = require('./x').fn
        init = init.getExpression();
      }
      if (!init || !Node.isCallExpression(init) || init.getExpression().getText() !== "require") continue;
      const arg = init.getArguments()[0];
      if (!arg || !Node.isStringLiteral(arg)) continue;
      const spec = arg.getLiteralValue();
      const nameNode = decl.getNameNode();

      if (Node.isIdentifier(nameNode)) {
        map.set(nameNode.getText(), member ? { kind: "named", spec, imported: member } : { kind: "namespace", spec });
      } else if (Node.isObjectBindingPattern(nameNode)) {
        for (const el of nameNode.getElements()) {
          map.set(el.getName(), { kind: "named", spec, imported: el.getPropertyNameNode()?.getText() ?? el.getName() });
        }
      }
    }

    for (const imp of sf.getImportDeclarations()) {
      const spec = imp.getModuleSpecifierValue();
      const def = imp.getDefaultImport();
      if (def) map.set(def.getText(), { kind: "namespace", spec }); // CommonJS interop: default import is module.exports
      const ns = imp.getNamespaceImport();
      if (ns) map.set(ns.getText(), { kind: "namespace", spec });
      for (const named of imp.getNamedImports()) {
        map.set(named.getAliasNode()?.getText() ?? named.getName(), { kind: "named", spec, imported: named.getName() });
      }
    }

    this.bindingsCache.set(sf, map);
    return map;
  }

  /** Top-level `function name` or `const name = (…) => …` / `function (…)`. */
  private findFunction(sf: SourceFile, name: string): Fn | undefined {
    const decl = sf.getFunction(name);
    if (decl) return decl;
    const init = sf.getVariableDeclaration(name)?.getInitializer();
    return init && isFn(init) ? init : undefined;
  }

  /** Resolves an exported name via `module.exports = { … }`, `exports.name = …`, or an ES export. */
  private findExport(sf: SourceFile, name: string): Fn | undefined {
    for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      if (bin.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
      const left = bin.getLeft().getText();
      const right = bin.getRight();

      if (left === "module.exports" && Node.isObjectLiteralExpression(right)) {
        const prop = right.getProperty(name);
        if (Node.isShorthandPropertyAssignment(prop)) return this.findFunction(sf, name);
        if (Node.isPropertyAssignment(prop)) {
          const value = prop.getInitializer();
          if (value && isFn(value)) return value;
          if (value && Node.isIdentifier(value)) return this.findFunction(sf, value.getText());
        }
      }
      if (left === `exports.${name}` || left === `module.exports.${name}`) {
        if (isFn(right)) return right;
        if (Node.isIdentifier(right)) return this.findFunction(sf, right.getText());
      }
    }
    return this.findFunction(sf, name);
  }
}

/** Traces request input from every handler in `entry` across files to SQL-executing calls. */
export function traceEntry(entry: string, root = findProjectRoot(entry)): TraceResult {
  const tracer = new Tracer(path.resolve(root));
  const sf = tracer.load(path.resolve(entry));
  const handlers = tracer.handlers(sf);
  for (const { fn, req } of handlers) tracer.analyze(fn, new Map(), 0, req);

  const paths = [...tracer.paths].sort((a, b) => {
    const sa = a.hops.at(-1)!;
    const sb = b.hops.at(-1)!;
    return Number(b.sqlText) - Number(a.sqlText) || sa.file.localeCompare(sb.file) || sa.line - sb.line || a.hops[0].line - b.hops[0].line;
  });
  return { root: tracer.root, entry: path.relative(tracer.root, path.resolve(entry)), handlers: handlers.length, paths, unresolved: tracer.unresolved };
}
