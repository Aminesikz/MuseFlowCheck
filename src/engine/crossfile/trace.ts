// Stage 1 of cross-file analysis: a deterministic (no LLM) call-graph taint tracer built on ts-morph.
// Scope: tainted values passed as call arguments across require()/import boundaries. Callees are resolved
// syntactically (no type checker) so every resolved edge — and every one that breaks — can be explained.
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import {
  Node,
  Project,
  SyntaxKind,
  type ArrowFunction,
  type BinaryExpression,
  type CallExpression,
  type ClassDeclaration,
  type ClassExpression,
  type FunctionDeclaration,
  type FunctionExpression,
  type MethodDeclaration,
  type ObjectLiteralExpression,
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

/** A tainted call into project code that the tracer could not follow — the place a trace breaks. */
export interface UnresolvedCall {
  file: string;
  line: number;
  call: string;
  reason: string;
}

/** A tainted call whose callee lives outside the project (a package, a global, a caller-supplied parameter). */
export interface ExternalCall {
  file: string;
  line: number;
  call: string;
  target: string;
}

export interface TraceResult {
  root: string;
  entry: string;
  /** Request-handler functions traced: those in the entry file plus those it references from other files. */
  handlers: number;
  paths: CandidatePath[];
  unresolved: UnresolvedCall[];
  external: ExternalCall[];
}

type Fn = FunctionDeclaration | ArrowFunction | FunctionExpression | MethodDeclaration;
type Cls = ClassDeclaration | ClassExpression;
interface Taint {
  origin: string;
  hops: Hop[];
}
type Env = Map<string, Taint[]>;

/** What an expression statically refers to, as far as the tracer can tell. */
type Value =
  | { kind: "function"; fn: Fn }
  | { kind: "module"; sf: SourceFile }
  | { kind: "object"; obj: ObjectLiteralExpression }
  | { kind: "class"; cls: Cls }
  | { kind: "instance"; cls: Cls }
  | { kind: "external"; what: string }
  | { kind: "unresolved"; reason: string };
type ProjectValue = Extract<Value, { kind: "module" | "object" | "class" | "instance" }>;
type Callee = Value | { kind: "sink" };

/** Request properties that carry attacker-controlled input. */
const SOURCE_PROPS = new Set(["query", "params", "body"]);
/** Methods that execute SQL when called on something that isn't a project function (pool.query, client.query, db.query, …). */
const SINK_METHODS = new Set(["query", "execute"]);
const MODULE_EXTENSIONS = ["", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts", "/index.js", "/index.ts", "/index.mjs", "/index.cjs"];
const MAX_DEPTH = 8;

function isFn(node: Node | undefined): node is Fn {
  return (
    Node.isFunctionDeclaration(node) || Node.isArrowFunction(node) || Node.isFunctionExpression(node) || Node.isMethodDeclaration(node)
  );
}

function isProjectValue(v: Value): v is ProjectValue {
  return v.kind === "module" || v.kind === "object" || v.kind === "class" || v.kind === "instance";
}

function excerpt(node: Node, max = 140): string {
  const text = node.getText().replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Strips wrappers that don't change what an expression refers to. */
function unwrap(node: Node): Node {
  let n = node;
  while (
    Node.isAwaitExpression(n) ||
    Node.isParenthesizedExpression(n) ||
    Node.isAsExpression(n) ||
    Node.isNonNullExpression(n) ||
    Node.isSatisfiesExpression(n) ||
    Node.isTypeAssertion(n)
  ) {
    n = n.getExpression();
  }
  return n;
}

/** A property or binding key as written: identifier text or string-literal value. */
function keyName(node: Node): string {
  return Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node) ? node.getLiteralValue() : node.getText();
}

/** The member name of `a.b` / `a['b']`; undefined for computed access. */
function memberName(node: Node): string | undefined {
  if (Node.isPropertyAccessExpression(node)) return node.getName();
  if (Node.isElementAccessExpression(node)) {
    const arg = node.getArgumentExpression();
    if (arg && (Node.isStringLiteral(arg) || Node.isNoSubstitutionTemplateLiteral(arg))) return arg.getLiteralValue();
  }
  return undefined;
}

/** How to describe a receiver the tracer does not model (built-in methods on literals, untracked expressions). */
function literalKind(node: Node): string {
  if (Node.isArrayLiteralExpression(node)) return "array value";
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node) || Node.isTemplateExpression(node)) return "string value";
  if (Node.isNumericLiteral(node)) return "number value";
  return `untracked ${node.getKindName()}`;
}

/** The declaration named `name` inside a binding name: the owner itself, or a destructured element. */
function declIn(nameNode: Node, name: string, owner: Node): Node | undefined {
  if (Node.isIdentifier(nameNode)) return nameNode.getText() === name ? owner : undefined;
  return nameNode
    .getDescendantsOfKind(SyntaxKind.BindingElement)
    .find((b) => Node.isIdentifier(b.getNameNode()) && b.getName() === name);
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
  private readonly onStack = new Set<Fn>();
  private readonly pathKeys = new Set<string>();
  private readonly edgeKeys = new Set<string>();
  /** Declarations / exports currently being resolved, to stop on circular definitions and re-exports. */
  private readonly resolvingDecls = new Set<Node>();
  private readonly resolvingExports = new Set<string>();
  readonly paths: CandidatePath[] = [];
  readonly unresolved: UnresolvedCall[] = [];
  readonly external: ExternalCall[] = [];

  constructor(readonly root: string) {}

  load(file: string): SourceFile {
    return this.project.getSourceFile(file) ?? this.project.addSourceFileAtPath(file);
  }

  /** Request handlers in a file: functions whose first parameter is read as `<param>.query|params|body`. */
  handlers(sf: SourceFile): { fn: Fn; req: string }[] {
    const found: { fn: Fn; req: string }[] = [];
    for (const node of sf.getDescendants()) {
      const req = isFn(node) ? this.handlerReq(node) : undefined;
      if (req) found.push({ fn: node as Fn, req });
    }
    return found;
  }

  /**
   * Handlers defined in other files but referenced from this one, e.g. `router.get('/x', controller.list)`.
   * Only arguments of calls outside function bodies (route registration) are considered.
   */
  referencedHandlers(sf: SourceFile): { fn: Fn; req: string }[] {
    const found = new Map<Fn, string>();
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (call.getFirstAncestor(isFn)) continue;
      for (const arg of call.getArguments()) {
        if (!Node.isIdentifier(arg) && !Node.isPropertyAccessExpression(arg)) continue;
        const v = this.resolveExpr(arg);
        if (v.kind !== "function" || v.fn.getSourceFile() === sf) continue;
        const req = this.handlerReq(v.fn);
        if (req) found.set(v.fn, req);
      }
    }
    return [...found].map(([fn, req]) => ({ fn, req }));
  }

  private handlerReq(fn: Fn): string | undefined {
    const first = fn.getParameters()[0]?.getNameNode();
    if (!first || !Node.isIdentifier(first)) return undefined;
    const req = first.getText();
    return this.sourceAccesses(fn, req).length > 0 ? req : undefined;
  }

  // ---- naming / hops ----------------------------------------------------------------------

  private rel(sf: SourceFile): string {
    return path.relative(this.root, sf.getFilePath()) || sf.getBaseName();
  }

  /** `Class`, the variable an object literal is assigned to, or `module.exports` / `export default`. */
  private ownerName(owner: Node | undefined): string {
    if (Node.isClassDeclaration(owner) || Node.isClassExpression(owner)) return owner.getName() ?? "<class>";
    if (Node.isObjectLiteralExpression(owner)) {
      const p = owner.getParent();
      if (Node.isVariableDeclaration(p)) return p.getName();
      if (Node.isBinaryExpression(p)) return p.getLeft().getText();
      if (Node.isExportAssignment(p)) return "export default";
      const factory = Node.isReturnStatement(p) ? p.getFirstAncestor(isFn) : Node.isArrowFunction(p) ? p : undefined;
      if (factory) return `${this.fnName(factory)}()`;
    }
    return "<object>";
  }

  private fnName(fn: Fn): string {
    if (Node.isMethodDeclaration(fn)) return `${this.ownerName(fn.getParent())}.${fn.getName()}`;
    if (Node.isFunctionDeclaration(fn) && fn.getName()) return fn.getName()!;
    const parent = fn.getParent();
    if (Node.isVariableDeclaration(parent)) return parent.getName();
    if (Node.isPropertyAssignment(parent)) return `${this.ownerName(parent.getParent())}.${keyName(parent.getNameNode())}`;
    if (Node.isPropertyDeclaration(parent)) return `${this.ownerName(parent.getParent())}.${parent.getName()}`;
    if (Node.isBinaryExpression(parent)) return parent.getLeft().getText(); // exports.name = function …
    if (Node.isExportAssignment(parent) || (Node.isFunctionDeclaration(fn) && fn.isDefaultExport())) return "export default";
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

  private signature(fn: Fn): string {
    const body = fn.getBody();
    const head = body ? fn.getText().slice(0, body.getStart() - fn.getStart()) : fn.getText();
    const sig = head.replace(/\s+/g, " ").replace(/\s*(=>)?\s*$/, "").trim();
    if (Node.isFunctionDeclaration(fn)) return sig;
    if (Node.isMethodDeclaration(fn)) return sig.replace(fn.getName(), this.fnName(fn));
    return `${this.fnName(fn)} = ${sig}`;
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

  /**
   * New taints for request inputs read directly inside `expr` (e.g. a call argument `req.params.id`).
   * The hop points at the enclosing statement so multi-line calls read as one complete line of code.
   */
  private inlineSourceTaints(expr: Node, req: string | undefined, ref: FunctionRef): Taint[] {
    return this.sourceAccesses(expr, req).map((pa) => {
      const stmt =
        pa.getFirstAncestor(
          (a) => Node.isVariableStatement(a) || Node.isExpressionStatement(a) || Node.isReturnStatement(a),
        ) ?? pa;
      return {
        origin: `${this.rel(pa.getSourceFile())}:${pa.getStartLineNumber()}:${pa.getText()}`,
        hops: [this.hop(stmt, "source", ref)],
      };
    });
  }

  private exprTaints(expr: Node, env: Env, ref: FunctionRef, req?: string): Taint[] {
    return mergeTaints(this.inlineSourceTaints(expr, req, ref), this.idTaints(expr, env));
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

    const visit = (node: Node) => {
      if (Node.isVariableDeclaration(node)) this.onDeclaration(node, env, ref, req);
      else if (Node.isBinaryExpression(node)) this.onAssignment(node, env, ref, req);
      else if (Node.isCallExpression(node)) this.onCall(node, env, ref, depth, req);
    };
    if (!Node.isBlock(body)) visit(body); // expression-bodied arrow: `(x) => run(x)`
    body.forEachDescendant((node, traversal) => {
      if (isFn(node)) return traversal.skip(); // nested callbacks are not followed yet
      visit(node);
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
    const incoming = this.exprTaints(right, env, ref, req).map((t) => ({
      origin: t.origin,
      hops: [...t.hops, this.hop(bin, kind, ref)],
    }));

    const name = left.getText();
    const next = op === SyntaxKind.PlusEqualsToken ? mergeTaints(env.get(name) ?? [], incoming) : incoming;
    if (next.length > 0) env.set(name, next);
    else env.delete(name);
  }

  private onCall(call: CallExpression, env: Env, ref: FunctionRef, depth: number, req?: string): void {
    const argTaints = call.getArguments().map((arg) => this.exprTaints(arg, env, ref, req));
    if (argTaints.every((t) => t.length === 0)) return;

    const callee = this.resolveCallee(call);
    const at = { file: ref.file, line: call.getStartLineNumber(), call: excerpt(call.getExpression()) };
    switch (callee.kind) {
      case "function":
        return this.enterCallee(call, callee.fn, argTaints, env, ref, depth, req);
      case "sink":
        return this.recordSink(call, argTaints, ref);
      case "external":
        return this.addEdge(this.external, { ...at, target: callee.what });
      case "unresolved":
        return this.addEdge(this.unresolved, { ...at, reason: callee.reason });
      default:
        return this.addEdge(this.unresolved, { ...at, reason: `callee is a ${callee.kind}, not a function` });
    }
  }

  private addEdge<T extends { file: string; line: number; call: string }>(list: T[], edge: T): void {
    const key = `${edge.file}:${edge.line}:${edge.call}`;
    if (this.edgeKeys.has(key)) return;
    this.edgeKeys.add(key);
    list.push(edge);
  }

  // ---- interprocedural: argument → parameter ------------------------------------------------

  private enterCallee(call: CallExpression, fn: Fn, argTaints: Taint[][], env: Env, ref: FunctionRef, depth: number, req?: string): void {
    const calleeRef = this.fnRef(fn);
    const callHop = this.hop(call, "call", ref);
    const paramHop: Hop = { file: calleeRef.file, line: fn.getStartLineNumber(), code: this.signature(fn), kind: "param", fn: calleeRef };
    const calleeEnv: Env = new Map();
    const bind = (name: string, taints: Taint[]) => {
      if (taints.length === 0) return;
      const hops = [callHop, { ...paramHop, code: `${paramHop.code}  [param ${name}]` }];
      calleeEnv.set(name, mergeTaints(calleeEnv.get(name) ?? [], taints.map((t) => ({ origin: t.origin, hops: [...t.hops, ...hops] }))));
    };

    fn.getParameters().forEach((param, i) => {
      const taints = param.isRestParameter() ? argTaints.slice(i).reduce(mergeTaints, []) : (argTaints[i] ?? []);
      if (taints.length === 0) return;
      const nameNode = param.getNameNode();
      if (Node.isIdentifier(nameNode)) return bind(nameNode.getText(), taints);

      // Destructured parameter: map `{ a, b: c }` to the matching properties of an object-literal argument;
      // otherwise (whole tainted object, nested or array patterns, spreads) every bound name takes the argument's taint.
      const arg = call.getArguments()[i];
      const literal = arg && !param.isRestParameter() ? unwrap(arg) : undefined;
      const byKey = Node.isObjectLiteralExpression(literal) && !literal.getProperties().some(Node.isSpreadAssignment) ? literal : undefined;
      for (const el of nameNode.getDescendantsOfKind(SyntaxKind.BindingElement)) {
        if (!Node.isIdentifier(el.getNameNode())) continue;
        const topLevel = el.getParent() === nameNode && Node.isObjectBindingPattern(nameNode) && !el.getDotDotDotToken();
        if (!byKey || !topLevel) {
          bind(el.getName(), taints);
          continue;
        }
        const key = keyName(el.getPropertyNameNode() ?? el.getNameNode());
        const prop = byKey.getProperties().find((p) => (Node.isPropertyAssignment(p) || Node.isShorthandPropertyAssignment(p)) && keyName(p.getNameNode()) === key);
        const value = Node.isPropertyAssignment(prop) ? prop.getInitializer() : Node.isShorthandPropertyAssignment(prop) ? prop.getNameNode() : undefined;
        if (value) bind(el.getName(), this.exprTaints(value, env, ref, req));
      }
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

  // ---- call / value resolution --------------------------------------------------------------

  /**
   * What a call invokes. A method on a project module/object/class resolves to that member; a sink-named
   * method (`.query`, `.execute`) on anything else — a package object, a parameter — is treated as a SQL sink.
   */
  private resolveCallee(call: CallExpression): Callee {
    const expr = unwrap(call.getExpression());
    if (!Node.isPropertyAccessExpression(expr) && !Node.isElementAccessExpression(expr)) return this.resolveExpr(expr);

    const name = memberName(expr);
    const target = this.resolveExpr(expr.getExpression());
    if (isProjectValue(target)) {
      if (name === undefined) return { kind: "unresolved", reason: `computed member access ${excerpt(expr, 60)}` };
      return this.member(target, name) ?? { kind: "unresolved", reason: this.missingReason(target, name) };
    }
    if (name && SINK_METHODS.has(name)) return { kind: "sink" };
    if (target.kind === "function") {
      return { kind: "unresolved", reason: `indirect invocation '${excerpt(expr, 60)}' of project function ${this.fnName(target.fn)}` };
    }
    return target;
  }

  private resolveExpr(node: Node): Value {
    const e = unwrap(node);
    if (isFn(e)) return { kind: "function", fn: e };
    if (Node.isIdentifier(e)) return this.resolveName(e, e.getText());
    if (Node.isObjectLiteralExpression(e)) return { kind: "object", obj: e };
    if (Node.isClassExpression(e)) return { kind: "class", cls: e };
    if (Node.isThisExpression(e)) return this.resolveThis(e);
    if (Node.isNewExpression(e)) {
      const ctor = this.resolveExpr(e.getExpression());
      if (ctor.kind === "class") return { kind: "instance", cls: ctor.cls };
      if (ctor.kind === "function") return { kind: "unresolved", reason: `'new' on constructor function ${this.fnName(ctor.fn)}` };
      return ctor;
    }
    if (Node.isCallExpression(e)) return this.resolveCallResult(e);
    if (Node.isPropertyAccessExpression(e) || Node.isElementAccessExpression(e)) {
      const name = memberName(e);
      const target = this.resolveExpr(e.getExpression());
      if (target.kind === "external" || target.kind === "unresolved") return target;
      if (name === undefined) return { kind: "unresolved", reason: `computed member access ${excerpt(e, 60)}` };
      if (target.kind === "function") return { kind: "unresolved", reason: `property '${name}' of project function ${this.fnName(target.fn)}` };
      return this.member(target, name) ?? { kind: "unresolved", reason: this.missingReason(target, name) };
    }
    return { kind: "external", what: literalKind(e) };
  }

  /** `require('./x')`, `import('./x')`, a factory's single returned value, or the result of an external call. */
  private resolveCallResult(call: CallExpression): Value {
    const callee = call.getExpression();
    const isRequire = Node.isIdentifier(callee) && callee.getText() === "require" && !this.lookup(callee, "require");
    if (isRequire || callee.getKind() === SyntaxKind.ImportKeyword) {
      const arg = call.getArguments()[0];
      if (arg && (Node.isStringLiteral(arg) || Node.isNoSubstitutionTemplateLiteral(arg))) {
        return this.resolveImport(call.getSourceFile(), arg.getLiteralValue());
      }
      return { kind: "unresolved", reason: `dynamic ${isRequire ? "require" : "import"}(${arg ? excerpt(arg, 60) : ""}) — module path is computed at runtime` };
    }

    const target = this.resolveExpr(callee);
    if (target.kind !== "function") return isProjectValue(target) ? { kind: "unresolved", reason: `call of a non-function ${excerpt(callee, 60)}` } : target;
    const fn = target.fn;
    const body = fn.getBody();
    if (body && !Node.isBlock(body)) return this.guard(fn, () => this.resolveExpr(body));
    const returns = body
      ?.getDescendantsOfKind(SyntaxKind.ReturnStatement)
      .filter((r) => r.getFirstAncestor(isFn) === fn && r.getExpression());
    if (returns?.length === 1) return this.guard(fn, () => this.resolveExpr(returns[0].getExpression()!));
    return { kind: "unresolved", reason: `value returned by ${this.fnName(fn)} (${returns?.length ?? 0} return statements; only single-return factories are followed)` };
  }

  private guard(key: Node, resolve: () => Value): Value {
    if (this.resolvingDecls.has(key)) return { kind: "unresolved", reason: `circular definition at ${this.rel(key.getSourceFile())}:${key.getStartLineNumber()}` };
    this.resolvingDecls.add(key);
    try {
      return resolve();
    } finally {
      this.resolvingDecls.delete(key);
    }
  }

  private resolveThis(node: Node): Value {
    const owner = node.getFirstAncestor(
      (a) => Node.isFunctionDeclaration(a) || Node.isFunctionExpression(a) || Node.isMethodDeclaration(a) || Node.isConstructorDeclaration(a) || Node.isPropertyDeclaration(a),
    );
    const parent = Node.isFunctionExpression(owner) ? owner.getParent()?.getParent() : owner?.getParent();
    if (Node.isClassDeclaration(parent) || Node.isClassExpression(parent)) {
      const isStatic = (Node.isMethodDeclaration(owner) || Node.isPropertyDeclaration(owner)) && owner.isStatic();
      return { kind: isStatic ? "class" : "instance", cls: parent };
    }
    if (Node.isObjectLiteralExpression(parent)) return { kind: "object", obj: parent };
    return { kind: "unresolved", reason: "'this' outside a class or object method" };
  }

  private resolveName(from: Node, name: string): Value {
    const decl = this.lookup(from, name);
    if (!decl) return { kind: "external", what: `global '${name}'` };
    return this.guard(decl, () => this.resolveDecl(decl, name));
  }

  private resolveDecl(decl: Node, name: string): Value {
    if (Node.isFunctionDeclaration(decl)) return { kind: "function", fn: decl };
    if (Node.isClassDeclaration(decl)) return { kind: "class", cls: decl };
    if (Node.isParameterDeclaration(decl)) return this.parameterValue(decl.getParent(), name);
    if (Node.isVariableDeclaration(decl)) {
      const init = decl.getInitializer();
      return init ? this.resolveExpr(init) : { kind: "unresolved", reason: `'${name}' is declared without an initializer` };
    }
    if (Node.isBindingElement(decl)) return this.resolveBindingElement(decl, name);
    const spec = decl.getFirstAncestorByKind(SyntaxKind.ImportDeclaration)?.getModuleSpecifierValue();
    if (spec !== undefined) {
      if (Node.isImportSpecifier(decl)) return this.resolveImport(decl.getSourceFile(), spec, decl.getName());
      if (Node.isImportClause(decl)) return this.resolveImport(decl.getSourceFile(), spec, "default");
      if (Node.isNamespaceImport(decl)) return this.resolveImport(decl.getSourceFile(), spec);
    }
    return { kind: "unresolved", reason: `unsupported declaration of '${name}' (${decl.getKindName()})` };
  }

  /** A parameter's value is supplied by the caller; constructor-injected ones are project dependencies we can't see. */
  private parameterValue(owner: Node | undefined, name: string): Value {
    if (Node.isConstructorDeclaration(owner)) {
      return { kind: "unresolved", reason: `'${name}' is injected through the constructor of ${this.ownerName(owner.getParent())}; 'new' call sites are not followed` };
    }
    return { kind: "external", what: `parameter '${name}'` };
  }

  /** `const { a: { b } } = init` → member chain a.b of init. */
  private resolveBindingElement(el: Node, name: string): Value {
    const keys: string[] = [];
    let node: Node | undefined = el;
    while (Node.isBindingElement(node)) {
      const pattern: Node | undefined = node.getParent();
      if (!Node.isObjectBindingPattern(pattern)) return { kind: "unresolved", reason: `'${name}' comes from array destructuring` };
      keys.unshift(keyName(node.getPropertyNameNode() ?? node.getNameNode()));
      node = pattern.getParent();
    }
    if (Node.isParameterDeclaration(node)) return this.parameterValue(node.getParent(), name);
    const init = Node.isVariableDeclaration(node) ? node.getInitializer() : undefined;
    if (!init) return { kind: "unresolved", reason: `'${name}' is destructured from a value the tracer cannot see` };
    let v = this.resolveExpr(init);
    for (const key of keys) {
      if (!isProjectValue(v)) return v.kind === "function" ? { kind: "unresolved", reason: `property '${key}' of project function ${this.fnName(v.fn)}` } : v;
      const m = this.member(v, key);
      if (!m) return { kind: "unresolved", reason: this.missingReason(v, key) };
      v = m;
    }
    return v;
  }

  /** Lexical lookup of `name` from `from` outward: parameters, block/file statements, imports. */
  private lookup(from: Node, name: string): Node | undefined {
    for (let scope = from.getParent(); scope; scope = scope.getParent()) {
      if (isFn(scope) || Node.isConstructorDeclaration(scope)) {
        for (const p of scope.getParameters()) {
          const hit = declIn(p.getNameNode(), name, p);
          if (hit) return hit;
        }
      }
      if (Node.isCatchClause(scope)) {
        const v = scope.getVariableDeclaration();
        const hit = v && declIn(v.getNameNode(), name, v);
        if (hit) return hit;
      }
      if (Node.isForOfStatement(scope) || Node.isForInStatement(scope) || Node.isForStatement(scope)) {
        const init = scope.getInitializer();
        if (Node.isVariableDeclarationList(init)) {
          for (const d of init.getDeclarations()) {
            const hit = declIn(d.getNameNode(), name, d);
            if (hit) return hit;
          }
        }
      }
      if (Node.isSourceFile(scope) || Node.isBlock(scope) || Node.isModuleBlock(scope) || Node.isCaseClause(scope) || Node.isDefaultClause(scope)) {
        for (const st of scope.getStatements()) {
          const hit = this.declaredBy(st, name);
          if (hit) return hit;
        }
      }
    }
    return undefined;
  }

  private declaredBy(st: Node, name: string): Node | undefined {
    if (Node.isVariableStatement(st)) {
      for (const d of st.getDeclarations()) {
        const hit = declIn(d.getNameNode(), name, d);
        if (hit) return hit;
      }
    }
    if ((Node.isFunctionDeclaration(st) || Node.isClassDeclaration(st)) && st.getName() === name) return st;
    if (Node.isImportDeclaration(st)) {
      if (st.getDefaultImport()?.getText() === name) return st.getImportClause();
      const ns = st.getNamespaceImport();
      if (ns?.getText() === name) return ns.getParent();
      return st.getNamedImports().find((n) => (n.getAliasNode()?.getText() ?? n.getName()) === name);
    }
    return undefined;
  }

  /** A named member of a project value; undefined when the value has no such member. */
  private member(v: ProjectValue, name: string): Value | undefined {
    switch (v.kind) {
      case "module":
        return this.exportOf(v.sf, name);
      case "object":
        return this.propertyOf(v.obj, name);
      case "class":
      case "instance":
        return this.classMember(v.cls, name, v.kind === "class");
    }
  }

  private missingReason(v: ProjectValue, name: string): string {
    switch (v.kind) {
      case "module":
        return `${this.rel(v.sf)} has no export '${name}'`;
      case "object":
        return `object at ${this.rel(v.obj.getSourceFile())}:${v.obj.getStartLineNumber()} has no property '${name}'`;
      default:
        return `class ${v.cls.getName() ?? "<anonymous>"} has no ${v.kind === "class" ? "static " : ""}member '${name}'`;
    }
  }

  /** `{ m() {} }`, `{ m: fn }`, `{ m }`, and `{ ...other }` (later properties win). */
  private propertyOf(obj: ObjectLiteralExpression, name: string): Value | undefined {
    const props = obj.getProperties();
    let blocked: Value | undefined;
    for (let i = props.length - 1; i >= 0; i--) {
      const p = props[i];
      if (Node.isSpreadAssignment(p)) {
        const spread = this.resolveExpr(p.getExpression());
        const m = isProjectValue(spread) ? this.member(spread, name) : undefined;
        if (m) return m;
        if (spread.kind === "unresolved") blocked ??= { kind: "unresolved", reason: `'${name}' may come from a spread the tracer cannot see: ${spread.reason}` };
        continue;
      }
      if (Node.isMethodDeclaration(p) && p.getName() === name) return { kind: "function", fn: p };
      if (Node.isShorthandPropertyAssignment(p) && p.getName() === name) return this.resolveExpr(p.getNameNode());
      if (Node.isPropertyAssignment(p) && keyName(p.getNameNode()) === name) return this.resolveExpr(p.getInitializerOrThrow());
    }
    return blocked;
  }

  /** Methods and fields of a class (and its project base classes); `this.x = …` in the constructor counts as a field. */
  private classMember(cls: Cls, name: string, isStatic: boolean): Value | undefined {
    for (const m of cls.getMembers()) {
      if (Node.isMethodDeclaration(m) && m.getName() === name && m.isStatic() === isStatic) return { kind: "function", fn: m };
      if (Node.isPropertyDeclaration(m) && m.getName() === name && m.isStatic() === isStatic) {
        const init = m.getInitializer();
        return init ? this.resolveExpr(init) : { kind: "unresolved", reason: `field '${name}' of class ${cls.getName() ?? "<anonymous>"} has no initializer` };
      }
    }
    if (!isStatic) {
      for (const ctor of cls.getConstructors()) {
        const prop = ctor.getParameters().find((p) => p.isParameterProperty() && p.getName() === name);
        if (prop) return this.parameterValue(ctor, name);
        for (const bin of ctor.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
          const left = bin.getLeft();
          if (bin.getOperatorToken().getKind() !== SyntaxKind.EqualsToken || !Node.isPropertyAccessExpression(left)) continue;
          if (Node.isThisExpression(left.getExpression()) && left.getName() === name) return this.resolveExpr(bin.getRight());
        }
      }
    }
    const base = cls.getExtends()?.getExpression();
    if (!base) return undefined;
    const parent = this.resolveExpr(base);
    return parent.kind === "class" ? this.classMember(parent.cls, name, isStatic) : isProjectValue(parent) ? undefined : parent;
  }

  private resolveImport(from: SourceFile, spec: string, name?: string): Value {
    if (!spec.startsWith(".") && !path.isAbsolute(spec)) return { kind: "external", what: `package '${spec}'` };
    const target = this.resolveModule(from, spec);
    if (!target) return { kind: "unresolved", reason: `cannot resolve module '${spec}' from ${this.rel(from)}` };
    if (name === undefined) return { kind: "module", sf: target };
    return this.exportOf(target, name) ?? { kind: "unresolved", reason: `'${spec}' resolves to ${this.rel(target)}, which has no export '${name}'` };
  }

  private exportOf(sf: SourceFile, name: string): Value | undefined {
    const key = `${sf.getFilePath()}#${name}`;
    if (this.resolvingExports.has(key)) return { kind: "unresolved", reason: `circular re-export of '${name}' through ${this.rel(sf)}` };
    this.resolvingExports.add(key);
    try {
      return this.findExport(sf, name);
    } finally {
      this.resolvingExports.delete(key);
    }
  }

  /**
   * Resolves an exported name through CommonJS (`exports.x =`, `module.exports = …`), ES declarations
   * (`export function`, `export const`, `export default`), and re-exports (`export { x } from`, `export *`).
   */
  private findExport(sf: SourceFile, name: string): Value | undefined {
    let whole: Node | undefined; // module.exports = … / export = …
    for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      if (bin.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
      const left = bin.getLeft().getText().replace(/\s+/g, "");
      if (left === `exports.${name}` || left === `module.exports.${name}`) return this.resolveExpr(bin.getRight());
      if (left === "module.exports") whole = bin.getRight();
    }
    whole = sf.getExportAssignment((a) => a.isExportEquals())?.getExpression() ?? whole;

    if (name === "default") {
      const assignment = sf.getExportAssignment((a) => !a.isExportEquals());
      if (assignment) return this.resolveExpr(assignment.getExpression());
      const fn = sf.getFunctions().find((f) => f.isDefaultExport());
      if (fn) return { kind: "function", fn };
      const cls = sf.getClasses().find((c) => c.isDefaultExport());
      if (cls) return { kind: "class", cls };
    }

    const fn = sf.getFunction(name);
    if (fn?.isExported()) return { kind: "function", fn };
    const variable = sf.getVariableDeclaration(name);
    if (variable?.getVariableStatement()?.isExported()) return this.resolveDecl(variable, name);
    const cls = sf.getClass(name);
    if (cls?.isExported()) return { kind: "class", cls };

    for (const ed of sf.getExportDeclarations()) {
      const spec = ed.getModuleSpecifierValue();
      for (const ne of ed.getNamedExports()) {
        if ((ne.getAliasNode()?.getText() ?? ne.getName()) !== name) continue;
        return spec ? this.resolveImport(sf, spec, ne.getName()) : this.resolveName(ne, ne.getName());
      }
      if (!spec || !ed.isNamespaceExport()) continue;
      const nsName = ed.getNamespaceExport()?.getName();
      if (nsName !== undefined) {
        if (nsName === name) return this.resolveImport(sf, spec); // export * as ns from …
        continue;
      }
      const target = this.resolveImport(sf, spec); // export * from …
      if (target.kind === "module") {
        const m = this.exportOf(target.sf, name);
        if (m) return m;
      } else if (target.kind === "unresolved") {
        return { kind: "unresolved", reason: `'${name}' may come from 'export * from ${spec}': ${target.reason}` };
      }
    }

    if (whole) {
      const value = this.resolveExpr(whole);
      if (name === "default") return value; // CommonJS interop: the default import is module.exports
      return isProjectValue(value) ? this.member(value, name) : value;
    }
    if (name === "default") return { kind: "module", sf }; // `exports.x = …` only: default import is the exports object
    return undefined;
  }

  private resolveModule(from: SourceFile, spec: string): SourceFile | undefined {
    const base = path.resolve(path.dirname(from.getFilePath()), spec);
    const bases = /\.(m|c)?js$/.test(spec) ? [base, base.replace(/\.(m|c)?js$/, ".$1ts")] : [base];
    for (const b of bases) {
      for (const ext of MODULE_EXTENSIONS) {
        const candidate = b + ext;
        if (existsSync(candidate) && statSync(candidate).isFile()) return this.load(candidate);
      }
    }
    return undefined;
  }
}

/** Traces request input from every handler in `entry` (or referenced by it) across files to SQL-executing calls. */
export function traceEntry(entry: string, root = findProjectRoot(entry)): TraceResult {
  const tracer = new Tracer(path.resolve(root));
  const sf = tracer.load(path.resolve(entry));
  const handlers = [...tracer.handlers(sf), ...tracer.referencedHandlers(sf)];
  for (const { fn, req } of handlers) tracer.analyze(fn, new Map(), 0, req);

  const paths = [...tracer.paths].sort((a, b) => {
    const sa = a.hops.at(-1)!;
    const sb = b.hops.at(-1)!;
    return Number(b.sqlText) - Number(a.sqlText) || sa.file.localeCompare(sb.file) || sa.line - sb.line || a.hops[0].line - b.hops[0].line;
  });
  return {
    root: tracer.root,
    entry: path.relative(tracer.root, path.resolve(entry)),
    handlers: handlers.length,
    paths,
    unresolved: tracer.unresolved,
    external: tracer.external,
  };
}
