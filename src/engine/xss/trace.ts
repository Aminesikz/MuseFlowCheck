// Stage 1 of XSS analysis: the cross-file tracer, extended to find where request input is placed into HTML output.
// Every tainted value that reaches markup is classified by what happened to it on the way: still raw input text
// (a candidate for the model), encoded by a step that replaces "<" with an entity (listed, never sent), or already
// part of markup built earlier (that earlier build is where it was judged). Encoding is recognized by behavior —
// what a function's code does — not by its name, so a helper called `escape` that does not encode is still a sink.
import path from "node:path";
import { Node, SyntaxKind, type CallExpression, type SourceFile, type VariableDeclaration } from "ts-morph";
import {
  excerpt,
  isFn,
  memberName,
  traceProject,
  Tracer,
  unwrap,
  type Env,
  type Fn,
  type FunctionRef,
  type Hop,
  type Req,
  type Taint,
  type TraceResult,
  type Value,
} from "../crossfile/trace.js";

/** What a tainted value is when it reaches output: raw input text, HTML-encoded text, or markup already built around it. */
export type TaintState = "text" | "encoded" | "html";

interface XssTaint extends Taint {
  state?: TaintState; // undefined means "text"
  /** The encoding step a value passed, e.g. `escapeHtml (views/html.js:11)`. */
  encoder?: string;
}

export interface XssPath {
  /** Ordered source → … → output. */
  hops: Hop[];
  origin: string;
  route?: string;
  /** "markup": interpolated or concatenated into a string containing HTML; "response": written to the response as-is. */
  context: "markup" | "response";
  /** True when the value passed an HTML-encoding step first: listed for transparency, not sent to the model. */
  encoded: boolean;
  encoder?: string;
  /** Top-level require/import statements of the output's file, so a patch can reuse an encoder it already has. */
  sinkImports: string[];
}

export interface XssTraceResult extends TraceResult {
  xss: XssPath[];
}

/** Literal text that makes a string HTML: a tag, a closing tag, a comment/doctype, or a character entity. */
const MARKUP = /<[a-zA-Z!/]|&(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#x[0-9a-fA-F]+);/;
/** A replacement that encodes "<": the named entity, or a numeric one (literal, or built from the character code). */
const ENCODES_LT = /&lt;|&#0*60;|&#x0*3c;|&#['"`]?\s*\+[^]*\b(?:charCodeAt|codePointAt)\b/i;
/** Globals whose result is a number or boolean, so it cannot carry markup. */
const NON_STRING_GLOBALS = new Set(["Number", "parseInt", "parseFloat", "Boolean", "isNaN", "isFinite", "Math", "Date"]);
/** Globals that percent-encode "<", '"' and "'"-free text: their output cannot open a tag. */
const URI_ENCODERS = new Set(["encodeURIComponent", "encodeURI"]);
/** Packages whose functions HTML-encode or sanitize (their decode/unescape functions excepted). */
const ENCODING_PACKAGES = new Set([
  "escape-html",
  "html-escaper",
  "he",
  "entities",
  "html-entities",
  "xss",
  "xss-filters",
  "sanitize-html",
  "dompurify",
  "isomorphic-dompurify",
  "escape-goat",
  "lodash.escape",
]);
/** General-purpose packages with an HTML-encoding function among others (lodash/underscore `escape`, validator `escape`). */
const UTILITY_PACKAGES = new Set(["lodash", "lodash-es", "underscore", "validator"]);
/** String/array methods whose result is not a string that could carry markup. */
const NON_STRING_METHODS = new Set([
  "indexOf",
  "lastIndexOf",
  "includes",
  "startsWith",
  "endsWith",
  "test",
  "some",
  "every",
  "findIndex",
  "localeCompare",
  "charCodeAt",
  "codePointAt",
  "search",
]);
/** Receivers whose `.send/.write/.end` writes an HTTP response body (Express/Node `res`, Fastify `reply`). */
const RESPONSE_OBJECT = /^(?:res|response|reply)$/;
const RESPONSE_WRITES = new Set(["send", "write", "end"]);
/** How deep return-value summaries follow nested project calls. */
const SUMMARY_DEPTH = 6;
const RANK: Record<TaintState, number> = { encoded: 0, html: 1, text: 2 };

/** Where an expression is being evaluated: in a traced function (hops are recorded) or inside a return-value summary. */
interface Scope {
  ref?: FunctionRef;
  req?: Req;
  depth: number;
}

const stateOf = (t: XssTaint): TaintState => t.state ?? "text";

/** Merges taints by origin, keeping the riskiest state seen for each (raw text over built markup over encoded). */
function merge(...lists: XssTaint[][]): XssTaint[] {
  const out = new Map<string, XssTaint>();
  for (const t of lists.flat()) {
    const seen = out.get(t.origin);
    if (!seen || RANK[stateOf(t)] > RANK[stateOf(seen)]) out.set(t.origin, t);
  }
  return [...out.values()];
}

/** The operands of a `+` chain, left to right: `'<b>' + x + '</b>'` → three nodes. */
function plusOperands(node: Node): Node[] {
  const e = Node.isParenthesizedExpression(node) ? node.getExpression() : node;
  if (Node.isBinaryExpression(e) && e.getOperatorToken().getKind() === SyntaxKind.PlusToken) {
    return [...plusOperands(e.getLeft()), ...plusOperands(e.getRight())];
  }
  return [node];
}

const isPlus = (n: Node | undefined) => Node.isBinaryExpression(n) && n.getOperatorToken().getKind() === SyntaxKind.PlusToken;

/** True for the outermost `+` of a chain (an operand chain, possibly parenthesized, is handled with its parent). */
function isChainTop(node: Node): boolean {
  const parent = node.getParent();
  return isPlus(node) && !isPlus(parent) && !(Node.isParenthesizedExpression(parent) && isPlus(parent.getParent()));
}

/** String-literal text of a node, or undefined when it is not a literal. */
function literalText(node: Node): string | undefined {
  const e = unwrap(node);
  return Node.isStringLiteral(e) || Node.isNoSubstitutionTemplateLiteral(e) ? e.getLiteralText() : undefined;
}

export class XssTracer extends Tracer {
  readonly xssPaths: XssPath[] = [];
  private readonly xssKeys = new Set<string>();
  private readonly summaries = new Map<string, XssTaint[]>();
  private readonly summarizing = new Set<Fn>();

  // ---- the shared walk, with XSS semantics -------------------------------------------------

  /** Taint carried into callees, assignments and object properties: classified, not just "mentions a tainted name". */
  protected override exprTaints(expr: Node, env: Env, ref: FunctionRef, req?: Req): Taint[] {
    return this.taintsOf(expr, env, { ref, req, depth: 0 });
  }

  protected override onDeclaration(decl: VariableDeclaration, env: Env, ref: FunctionRef, req?: Req): void {
    const init = decl.getInitializer();
    if (!init) return;
    const nameNode = decl.getNameNode();
    const names = Node.isIdentifier(nameNode)
      ? [nameNode.getText()]
      : nameNode.getDescendantsOfKind(SyntaxKind.BindingElement).map((b) => b.getName());
    const stmt = decl.getFirstAncestorByKind(SyntaxKind.VariableStatement) ?? decl;
    const kind = this.isStringBuild(init) ? "build" : "propagate";
    const here = (h: Hop | undefined) => h?.file === ref.file && h.line === stmt.getStartLineNumber();
    // A source read in this very statement already carries its hop here; anything flowing in gets one.
    const taints = this.taintsOf(init, env, { ref, req, depth: 0 }).map((t) =>
      here(t.hops.at(-1)) ? t : { ...t, hops: [...t.hops, this.hop(stmt, kind, ref)] },
    );
    for (const name of names) {
      if (taints.length > 0) env.set(name, taints);
      else env.delete(name);
    }
  }

  /** SQL execution is another analysis's sink. */
  protected override recordSink(): void {}

  protected override visitNode(node: Node, env: Env, ref: FunctionRef, req?: Req): void {
    const scope: Scope = { ref, req, depth: 0 };
    if (Node.isTemplateExpression(node)) {
      const literals = [node.getHead().getLiteralText(), ...node.getTemplateSpans().map((s) => s.getLiteral().getLiteralText())];
      this.onOutput(literals, node.getTemplateSpans().map((s) => s.getExpression()), env, scope);
    } else if (isChainTop(node)) {
      const operands = plusOperands(node);
      const literals = operands.map(literalText).filter((t): t is string => t !== undefined);
      this.onOutput(literals, operands.filter((o) => literalText(o) === undefined), env, scope);
    } else if (Node.isCallExpression(node)) {
      this.onResponseWrite(node, env, scope);
    }
  }

  /** A string built from literals and values: when the literals are HTML, every raw tainted value in it is an output. */
  private onOutput(literals: string[], values: Node[], env: Env, scope: Scope): void {
    if (!literals.some((t) => MARKUP.test(t))) return;
    for (const value of values) {
      for (const t of this.taintsOf(value, env, scope)) {
        if (stateOf(t) !== "html") this.record(t, value, "markup", scope.ref!);
      }
    }
  }

  /** `res.send(x)` / `res.status(200).write(x)`: raw input written straight to the response (Express sends strings as HTML). */
  private onResponseWrite(call: CallExpression, env: Env, scope: Scope): void {
    const callee = unwrap(call.getExpression());
    if (!Node.isPropertyAccessExpression(callee) || !RESPONSE_WRITES.has(callee.getName())) return;
    let root: Node = callee.getExpression();
    while (Node.isCallExpression(root) || Node.isPropertyAccessExpression(root)) root = unwrap(root.getExpression());
    if (!Node.isIdentifier(root) || !RESPONSE_OBJECT.test(root.getText())) return;
    const [body] = call.getArguments();
    if (!body || Node.isObjectLiteralExpression(unwrap(body)) || Node.isArrayLiteralExpression(unwrap(body))) return; // sent as JSON
    for (const t of this.taintsOf(body, env, scope)) {
      if (stateOf(t) !== "html") this.record(t, body, "response", scope.ref!);
    }
  }

  private record(t: XssTaint, value: Node, context: XssPath["context"], ref: FunctionRef): void {
    const sf = value.getSourceFile();
    const line = value.getStartLineNumber();
    const code = sf.getFullText().split(/\r?\n/)[line - 1].trim();
    const sink: Hop = { file: this.relPath(sf), line, code: code.length > 140 ? `${code.slice(0, 139)}…` : code, kind: "sink", fn: ref };
    const encoded = stateOf(t) === "encoded";
    const key = `${t.origin}->${sink.file}:${sink.line}:${encoded}`;
    if (this.xssKeys.has(key)) return;
    this.xssKeys.add(key);
    this.xssPaths.push({
      hops: [...t.hops, sink],
      origin: t.origin,
      ...(this.currentRoute ? { route: this.currentRoute } : {}),
      context,
      encoded,
      ...(encoded && t.encoder ? { encoder: t.encoder } : {}),
      sinkImports: imports(sf),
    });
  }

  // ---- classification of an expression's taint ------------------------------------------------

  private taintsOf(node: Node, env: Env, scope: Scope): XssTaint[] {
    const e = unwrap(node);
    if (Node.isIdentifier(e)) return (env.get(e.getText()) ?? []) as XssTaint[];
    if (Node.isPropertyAccessExpression(e) || Node.isElementAccessExpression(e)) {
      const source = this.sourceRead(e, scope);
      if (source) return [source];
      if (memberName(e) === "length") return [];
      return this.taintsOf(e.getExpression(), env, scope);
    }
    if (Node.isTemplateExpression(e)) {
      const literals = [e.getHead().getLiteralText(), ...e.getTemplateSpans().map((s) => s.getLiteral().getLiteralText())];
      return this.built(literals, e.getTemplateSpans().map((s) => s.getExpression()), env, scope);
    }
    if (Node.isBinaryExpression(e)) {
      const op = e.getOperatorToken().getKind();
      if (op === SyntaxKind.PlusToken) {
        const operands = plusOperands(e);
        const literals = operands.map(literalText).filter((t): t is string => t !== undefined);
        return this.built(literals, operands.filter((o) => literalText(o) === undefined), env, scope);
      }
      if (op === SyntaxKind.BarBarToken || op === SyntaxKind.QuestionQuestionToken || op === SyntaxKind.AmpersandAmpersandToken) {
        return merge(this.taintsOf(e.getLeft(), env, scope), this.taintsOf(e.getRight(), env, scope));
      }
      if (op === SyntaxKind.EqualsToken || op === SyntaxKind.CommaToken) return this.taintsOf(e.getRight(), env, scope);
      return []; // arithmetic and comparisons produce numbers and booleans
    }
    if (Node.isConditionalExpression(e)) return merge(this.taintsOf(e.getWhenTrue(), env, scope), this.taintsOf(e.getWhenFalse(), env, scope));
    if (Node.isCallExpression(e)) return this.callTaints(e, env, scope);
    if (Node.isArrayLiteralExpression(e)) return merge(...e.getElements().map((el) => this.taintsOf(el, env, scope)));
    if (Node.isSpreadElement(e) || Node.isSpreadAssignment(e)) return this.taintsOf(e.getExpression(), env, scope);
    if (Node.isObjectLiteralExpression(e)) {
      return merge(
        ...e.getProperties().map((p) => {
          if (Node.isPropertyAssignment(p)) return this.taintsOf(p.getInitializerOrThrow(), env, scope);
          if (Node.isShorthandPropertyAssignment(p)) return this.taintsOf(p.getNameNode(), env, scope);
          if (Node.isSpreadAssignment(p)) return this.taintsOf(p.getExpression(), env, scope);
          return [];
        }),
      );
    }
    if (Node.isTaggedTemplateExpression(e)) {
      const tpl = e.getTemplate();
      return Node.isTemplateExpression(tpl) ? merge(...tpl.getTemplateSpans().map((s) => this.taintsOf(s.getExpression(), env, scope))) : [];
    }
    if (Node.isNewExpression(e)) return merge(...(e.getArguments() ?? []).map((a) => this.taintsOf(a, env, scope)));
    return [];
  }

  /** A request read (`req.query.q`, `ctx.request.body.name`), as a new raw-text taint starting at its statement. */
  private sourceRead(e: Node, scope: Scope): XssTaint | undefined {
    if (!scope.req || !scope.ref) return undefined;
    for (let n: Node = e; Node.isPropertyAccessExpression(n) || Node.isElementAccessExpression(n); n = unwrap(n.getExpression())) {
      if (!Node.isPropertyAccessExpression(n) || !this.sourceAccesses(n, scope.req.name).includes(n)) continue;
      const stmt = e.getFirstAncestor((a) => Node.isVariableStatement(a) || Node.isExpressionStatement(a) || Node.isReturnStatement(a)) ?? e;
      return {
        origin: `${this.relPath(e.getSourceFile())}:${e.getStartLineNumber()}:${e.getText()}`,
        hops: [...scope.req.via, this.hop(stmt, "source", scope.ref)],
        state: "text",
      };
    }
    return undefined;
  }

  /** A string assembled from literal text and values: built markup when the literal text is HTML, else its values' taint. */
  private built(literals: string[], values: Node[], env: Env, scope: Scope): XssTaint[] {
    const inner = merge(...values.map((v) => this.taintsOf(v, env, scope)));
    return literals.some((t) => MARKUP.test(t)) ? inner.map((t) => ({ ...t, state: "html" as const })) : inner;
  }

  private callTaints(call: CallExpression, env: Env, scope: Scope): XssTaint[] {
    const callee = unwrap(call.getExpression());
    const args = call.getArguments();
    const receiver = Node.isPropertyAccessExpression(callee) || Node.isElementAccessExpression(callee) ? callee.getExpression() : undefined;
    const name = receiver ? memberName(callee) : Node.isIdentifier(callee) ? callee.getText() : undefined;
    const argTaints = () => args.map((a) => (isFn(unwrap(a)) ? [] : this.taintsOf(a, env, scope)));

    const resolved = this.resolveCallee(call);
    if (resolved.kind === "sink") return []; // a database read returns stored data, not this request's input
    if (resolved.kind === "function") {
      const fn = resolved.fn;
      const returned = this.summarize(fn, args, argTaints(), env, scope);
      if (!scope.ref) return returned;
      // The value comes back out of the callee: show the call and the callee, so its code is part of the evidence.
      const callHop = this.hop(call, "call", scope.ref);
      const calleeRef = this.functionRef(fn);
      return returned.map((t) => {
        const what = stateOf(t) === "text" ? "the value" : `${stateOf(t)} output`;
        const back: Hop = { file: calleeRef.file, line: fn.getStartLineNumber(), code: `${this.signature(fn)}  [returns ${what}]`, kind: "param", fn: calleeRef };
        return { ...t, hops: [...t.hops, callHop, back] };
      });
    }

    const encoder = this.encoderOf(resolved, name, receiver === undefined);
    if (encoder) {
      const label = `${excerpt(callee, 60)} (${encoder})`;
      return merge(...argTaints(), receiver ? this.taintsOf(receiver, env, scope) : []).map((t) => ({ ...t, state: "encoded" as const, encoder: label }));
    }
    if (receiver && (name === "replace" || name === "replaceAll")) {
      const base = this.taintsOf(receiver, env, scope);
      if (this.encodesLt(call)) {
        const at = Node.isPropertyAccessExpression(callee) ? callee.getNameNode() : call;
        const label = `.${name}(${excerpt(args[0], 30)}, …) at ${this.relPath(call.getSourceFile())}:${at.getStartLineNumber()}`;
        return base.map((t) => ({ ...t, state: "encoded" as const, encoder: label }));
      }
      return merge(base, args[1] ? this.taintsOf(args[1], env, scope) : []);
    }
    if (!receiver && resolved.kind === "external" && NON_STRING_GLOBALS.has(/^global '(.+)'$/.exec(resolved.what)?.[1] ?? "")) return [];
    if (receiver && Node.isIdentifier(receiver) && NON_STRING_GLOBALS.has(receiver.getText()) && !this.lookup(receiver, receiver.getText())) return [];
    if (receiver && name && NON_STRING_METHODS.has(name)) return [];
    if (receiver && (name === "map" || name === "flatMap") && args[0]) {
      const items = this.taintsOf(receiver, env, scope);
      const cb = this.resolveFunction(args[0]);
      return cb ? this.summarize(cb.fn, [], [items], env, scope) : items;
    }
    // Anything else — String(x), x.trim(), JSON.stringify(x), an unknown library call — passes its input through.
    return merge(receiver ? this.taintsOf(receiver, env, scope) : [], ...argTaints());
  }

  /** The encoder a resolved external callee is, when it is one: a percent-encoding global or an HTML-encoding package. */
  private encoderOf(v: Value | { kind: "sink" }, name: string | undefined, direct: boolean): string | undefined {
    if (v.kind !== "external") return undefined;
    const global = /^global '(.+)'$/.exec(v.what)?.[1];
    if (global) return direct && URI_ENCODERS.has(global) ? `global ${global}` : undefined;
    const pkg = /^package '(.+)'$/.exec(v.what)?.[1];
    if (!pkg || (name && /decode|unescape/i.test(name))) return undefined;
    const last = pkg.split("/").pop()!;
    if (ENCODING_PACKAGES.has(pkg) || /^(?:escape|encode|sanitize)/i.test(last)) return `package '${pkg}'`;
    if (UTILITY_PACKAGES.has(pkg.split("/")[0]) && name && /^(?:escape|encode|sanitize)/i.test(name)) return `package '${pkg}'`;
    return undefined;
  }

  /** `.replace(pattern, replacement)` that replaces "<" with an entity — the replacement may be a lookup table or callback. */
  private encodesLt(call: CallExpression): boolean {
    const [pattern, replacement] = call.getArguments();
    if (!pattern || !replacement) return false;
    const p = unwrap(pattern);
    const targetsLt = Node.isRegularExpressionLiteral(p) ? /<|\\x3c|\\u003c/i.test(p.getLiteralText()) : literalText(p)?.includes("<") === true;
    return targetsLt && ENCODES_LT.test(this.textWithReferences(replacement));
  }

  /** An expression's text plus the file-level declarations it refers to (e.g. an entity lookup table). */
  private textWithReferences(node: Node): string {
    const parts = [node.getText()];
    const ids = Node.isIdentifier(node) ? [node] : node.getDescendantsOfKind(SyntaxKind.Identifier);
    for (const id of ids) {
      const decl = this.lookup(id, id.getText());
      if (decl && (isFn(decl) || !decl.getFirstAncestor(isFn))) parts.push(decl.getText());
    }
    return parts.join("\n");
  }

  // ---- return-value summaries -------------------------------------------------------------

  /**
   * What a project function returns, given the taint of its arguments: its parameters are bound, its body's
   * declarations and assignments are followed in order, and its return expressions are classified. Pure — records
   * nothing (the walk itself visits the callee for outputs inside it).
   */
  private summarize(fn: Fn, args: Node[], argTaints: XssTaint[][], callerEnv: Env, scope: Scope): XssTaint[] {
    if (argTaints.every((t) => t.length === 0)) return [];
    if (this.summarizing.has(fn) || scope.depth >= SUMMARY_DEPTH) return merge(...argTaints);
    // Summaries are cached by origin and state; the hops are always this caller's own.
    const incoming = new Map(merge(...argTaints).map((t) => [t.origin, t.hops]));
    const ownHops = (ts: XssTaint[]) => ts.map((t) => ({ ...t, hops: incoming.get(t.origin) ?? t.hops }));
    const key = `${fn.getSourceFile().getFilePath()}:${fn.getStart()}|${argTaints.map((ts) => ts.map((t) => `${t.origin}=${stateOf(t)}`).join(",")).join("|")}`;
    const cached = this.summaries.get(key);
    if (cached) return ownHops(cached);

    const inner: Scope = { depth: scope.depth + 1 };
    const env: Env = new Map();
    fn.getParameters().forEach((param, i) => {
      const taints = param.isRestParameter() ? merge(...argTaints.slice(i)) : (argTaints[i] ?? []);
      const nameNode = param.getNameNode();
      if (Node.isIdentifier(nameNode)) {
        if (taints.length > 0) env.set(nameNode.getText(), taints);
        return;
      }
      const literal = args[i] ? unwrap(args[i]) : undefined;
      for (const el of nameNode.getDescendantsOfKind(SyntaxKind.BindingElement)) {
        let bound = taints;
        if (Node.isObjectLiteralExpression(literal) && el.getParent() === nameNode) {
          const key = el.getPropertyNameNode()?.getText() ?? el.getName();
          const prop = literal.getProperty(key);
          if (Node.isPropertyAssignment(prop)) bound = this.taintsOf(prop.getInitializerOrThrow(), callerEnv, scope);
          else if (Node.isShorthandPropertyAssignment(prop)) bound = this.taintsOf(prop.getNameNode(), callerEnv, scope);
        }
        if (bound.length > 0) env.set(el.getName(), bound);
      }
    });

    this.summarizing.add(fn);
    let returned: XssTaint[] = [];
    try {
      const body = fn.getBody();
      if (body && !Node.isBlock(body)) returned = this.taintsOf(body, env, inner);
      body?.forEachDescendant((node, traversal) => {
        if (isFn(node)) {
          traversal.skip();
          return;
        }
        if (Node.isVariableDeclaration(node) && node.getInitializer()) {
          const taints = this.taintsOf(node.getInitializer()!, env, inner);
          const nameNode = node.getNameNode();
          const names = Node.isIdentifier(nameNode) ? [nameNode.getText()] : nameNode.getDescendantsOfKind(SyntaxKind.BindingElement).map((b) => b.getName());
          for (const n of names) taints.length > 0 ? env.set(n, taints) : env.delete(n);
        } else if (Node.isBinaryExpression(node) && Node.isIdentifier(node.getLeft())) {
          const op = node.getOperatorToken().getKind();
          if (op !== SyntaxKind.EqualsToken && op !== SyntaxKind.PlusEqualsToken) return;
          const name = node.getLeft().getText();
          const right = this.taintsOf(node.getRight(), env, inner);
          const next = op === SyntaxKind.PlusEqualsToken ? merge((env.get(name) ?? []) as XssTaint[], right) : right;
          next.length > 0 ? env.set(name, next) : env.delete(name);
        } else if (Node.isReturnStatement(node) && node.getExpression()) {
          returned = merge(returned, this.taintsOf(node.getExpression()!, env, inner));
        }
      });
    } finally {
      this.summarizing.delete(fn);
    }
    this.summaries.set(key, returned);
    return ownHops(returned);
  }
}

/** Top-level `require(...)` / `import` statements of a file. */
function imports(sf: SourceFile): string[] {
  return sf
    .getStatements()
    .filter((st) => Node.isImportDeclaration(st) || (Node.isVariableStatement(st) && /\brequire\s*\(/.test(st.getText())))
    .map((st) => st.getText().replace(/\s+/g, " ").trim());
}

function sortXss(paths: XssPath[]): XssPath[] {
  return [...paths].sort((a, b) => {
    const [sa, sb] = [a.hops.at(-1)!, b.hops.at(-1)!];
    return Number(a.encoded) - Number(b.encoded) || sa.file.localeCompare(sb.file) || sa.line - sb.line || a.origin.localeCompare(b.origin);
  });
}

/** Traces every entry point of a project to HTML output, classifying each output as raw or encoded. */
export function traceXssProject(dir: string): XssTraceResult {
  const tracer = new XssTracer(path.resolve(dir));
  const trace = traceProject(dir, tracer);
  return { ...trace, xss: sortXss(tracer.xssPaths) };
}
