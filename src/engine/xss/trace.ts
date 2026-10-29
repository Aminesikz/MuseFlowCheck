// Stage 1 of XSS analysis: the cross-file tracer, extended to find where request input is placed into HTML output.
// Every tainted value that reaches an output is classified by what happened to it on the way: still raw input text
// (a candidate for the model), encoded by a step that replaces "<" with an entity (listed, never sent), or already
// part of markup built earlier (that earlier build is where it was judged). Encoding is recognized by behavior —
// what a function's code does — not by its name, so a helper called `escape` that does not encode is still a sink.
//
// Stored XSS spans two requests: one writes request input to the database, another reads it back and renders it.
// A first pass records which `table.column` each SQL write fills from raw request input; a second pass treats every
// read of such a column as a source — only that property of the returned record is tainted. Browser code (files of
// a package that depends on a UI library such as React) is then walked with server API responses as the source:
// a JSON response that carries a stored field passes it to whatever the browser fetches. There, only DOM HTML
// sinks count (`dangerouslySetInnerHTML`, `innerHTML`, …); a JSX text child is escaped by React and is listed as such.
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { Node, SyntaxKind, type CallExpression, type SourceFile, type VariableDeclaration } from "ts-morph";
import { discoverFiles } from "../crossfile/files.js";
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
  /** Set when only one property of the value is tainted — a stored column inside a record read from the database. */
  field?: string;
  /** For input that comes back out of storage: the `table.column` it was written to. */
  stored?: string;
  /** The HTTP route that read or served the stored value, when the output itself is not on a route (browser code). */
  route?: string;
  /** Who receives a stored value: decided by the route that serves it to the browser. */
  reach?: Reach;
}

/**
 * Who can receive a stored value, from the handler of the route that renders or serves it: anyone (it reads no
 * authenticated identity), any signed-in user (it reads one but does not restrict the record to it), or only the
 * scope that owns the record (it compares the record, or constrains its query, with the identity).
 */
export interface Reach {
  level: "public" | "authenticated" | "own-scope";
  route?: string;
  /** `file:line` of the handler, or of the identity check that scopes it. */
  at: string;
  code: string;
}

/** Where an output is: markup built as a string, the response body, the DOM as HTML, or a JSX text child. */
export type XssContext = "markup" | "response" | "dom-html" | "jsx-text";

export interface XssPath {
  /** Ordered source → … → output. For stored XSS: the write, then the read back, then the rendering. */
  hops: Hop[];
  origin: string;
  route?: string;
  context: XssContext;
  /** True when the value passed an HTML-encoding step first (or React escapes it): listed, not sent to the model. */
  encoded: boolean;
  encoder?: string;
  /** Top-level require/import statements of the output's file, so a patch can reuse an encoder it already has. */
  sinkImports: string[];
  /** Stored XSS: the `table.column` the input was persisted to, and the route that wrote it. */
  stored?: string;
  writtenBy?: string;
  /** Stored XSS: who receives the output (see Reach). */
  reach?: Reach;
}

export interface XssTraceResult extends TraceResult {
  xss: XssPath[];
}

/** A column filled from raw request input, with the path that wrote it. */
interface StoredWrite {
  origin: string;
  hops: Hop[];
  route?: string;
}

/** Literal text that makes a string HTML: a tag, a closing tag, a comment/doctype, or a character entity. */
const MARKUP = /<[a-zA-Z!/]|&(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#x[0-9a-fA-F]+);/;
/** A replacement that encodes "<": the named entity, or a numeric one (literal, or built from the character code). */
const ENCODES_LT = /&lt;|&#0*60;|&#x0*3c;|&#['"`]?\s*\+[^]*\b(?:charCodeAt|codePointAt)\b/i;
/** Globals whose result is a number or boolean, so it cannot carry markup. */
const NON_STRING_GLOBALS = new Set(["Number", "parseInt", "parseFloat", "Boolean", "isNaN", "isFinite", "Math", "Date"]);
/** Globals that percent-encode "<", so their output cannot open a tag. */
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
/** Methods whose callback receives the receiver's value as its first parameter: array elements, or a promise's result. */
const ELEMENT_CALLBACKS = new Set(["map", "flatMap", "forEach", "filter", "find", "findLast", "some", "every", "then"]);
/** Receivers whose `.send/.write/.end` writes an HTTP response body (Express/Node `res`, Fastify `reply`). */
const RESPONSE_OBJECT = /^(?:res|response|reply)$/;
const RESPONSE_WRITES = new Set(["send", "write", "end"]);
/** Packages that make browser code a UI client rather than a server. */
const UI_PACKAGES = ["react", "react-dom", "preact", "vue", "svelte", "solid-js"];
/** Ways browser code fetches from the server: the global `fetch`, or an HTTP client package. */
const HTTP_CLIENTS = new Set(["axios", "ky", "ofetch", "redaxios"]);
/** DOM properties and methods that parse a string as HTML. */
const DOM_HTML_PROPS = new Set(["innerHTML", "outerHTML"]);
const DOM_HTML_METHODS = new Set(["insertAdjacentHTML", "write", "writeln"]);
/** How deep return-value summaries follow nested project calls. */
const SUMMARY_DEPTH = 6;
const RANK: Record<TaintState, number> = { encoded: 0, html: 1, text: 2 };
/** Request properties that carry an authenticated identity, set by auth middleware (`req.user`, Koa `ctx.state.user`). */
const IDENTITY_PROPS = new Set(["user", "session", "auth"]);

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
    if (!seen || RANK[stateOf(t)] > RANK[stateOf(seen)] || (seen.field && !t.field)) out.set(t.origin, t);
  }
  return [...out.values()];
}

/** The taint of property `name` of a value: a record's stored field unwraps to the value itself; other properties pass. */
function member(taints: XssTaint[], name: string | undefined): XssTaint[] {
  return taints.map((t) => (t.field && name === t.field ? { ...t, field: undefined } : t));
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

// ---- SQL text: which columns a statement writes from which placeholder, and which it reads ------------------

const ident = (raw: string) => raw.trim().replace(/["`[\]]/g, "").split(".").pop()!.toLowerCase();

/** `UPDATE t SET a = $1, b = ?` / `INSERT INTO t (a, b) VALUES ($1, ?)`: the table and the parameter index per column. */
export function sqlWrite(sql: string): { table: string; columns: Map<string, number> } | undefined {
  const columns = new Map<string, number>();
  let positional = 0;
  const index = (token: string): number | undefined => {
    const t = token.trim();
    if (/^\$\d+$/.test(t)) return Number(t.slice(1)) - 1;
    if (t === "?") return positional++;
    return undefined;
  };
  const update = /^\s*update\s+([\w."`]+)\s+set\s+([\s\S]+?)(?:\s+where\b|\s+returning\b|\s*$)/i.exec(sql);
  if (update) {
    for (const assignment of update[2].split(",")) {
      const m = /^\s*([\w."`]+)\s*=\s*(\$\d+|\?)\s*$/.exec(assignment);
      if (!m) {
        if (assignment.includes("?")) positional += assignment.split("?").length - 1;
        continue;
      }
      const i = index(m[2]);
      if (i !== undefined) columns.set(ident(m[1]), i);
    }
    return { table: ident(update[1]), columns };
  }
  const insert = /^\s*insert\s+into\s+([\w."`]+)\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/i.exec(sql);
  if (insert) {
    const names = insert[2].split(",").map(ident);
    insert[3].split(",").forEach((value, n) => {
      const i = index(value);
      if (i !== undefined && names[n]) columns.set(names[n], i);
    });
    return { table: ident(insert[1]), columns };
  }
  return undefined;
}

/** `SELECT a, b AS c FROM t …` / `… RETURNING a, b`: the table and the property names the returned rows carry. */
export function sqlRead(sql: string): { table: string; columns: string[] } | undefined {
  const select = /^\s*select\s+([\s\S]+?)\s+from\s+([\w."`]+)/i.exec(sql);
  const returning = /^\s*(?:update|insert\s+into)\s+([\w."`]+)[\s\S]*?\breturning\s+([\s\S]+?)\s*;?\s*$/i.exec(sql);
  const [list, table] = select ? [select[1], select[2]] : returning ? [returning[2], returning[1]] : [];
  if (!list || !table) return undefined;
  const columns = list.split(",").map((c) => {
    const alias = /\s+(?:as\s+)?([\w"`]+)\s*$/i.exec(c.trim());
    return alias && /\s/.test(c.trim()) ? ident(alias[1]) : ident(c);
  });
  return { table: ident(table), columns };
}

export class XssTracer extends Tracer {
  readonly xssPaths: XssPath[] = [];
  /** Columns filled from raw request input (`table.column`), found by a first pass and given to the second. */
  readonly storedWrites: Map<string, StoredWrite>;
  /** Stored values the server sends as JSON, by `table.column` — what browser code can fetch. */
  private readonly exposures = new Map<string, XssTaint>();
  private readonly xssKeys = new Set<string>();
  private readonly summaries = new Map<string, XssTaint[]>();
  private readonly summarizing = new Set<Fn>();
  /** React state: the taint set into each `useState` declaration through its setter. */
  private readonly stateTaints = new Map<Node, XssTaint[]>();
  private readonly browserFiles = new Map<string, boolean>();
  /** Calls that led to the function being walked, so a stored read shows the route that renders it. */
  private chain: Hop[] = [];
  private pendingCall?: Hop;
  private analyzed = 0;
  private inBrowser = false;
  /** The request handler being walked (server side), whose code decides who receives what it renders. */
  private walking?: { fn: Fn; req?: string };
  private readonly reaches = new Map<Fn, Reach>();

  constructor(root: string, storedWrites?: Map<string, StoredWrite>) {
    super(root);
    this.storedWrites = storedWrites ?? new Map();
  }

  /** Enter callees and callbacks without tainted arguments too, once there is stored data they could read. */
  private get followAll(): boolean {
    return this.storedWrites.size > 0 || this.inBrowser;
  }

  // ---- the shared walk, with XSS semantics -------------------------------------------------

  /** Taint carried into callees, assignments and object properties: classified, not just "mentions a tainted name". */
  protected override exprTaints(expr: Node, env: Env, ref: FunctionRef, req?: Req): Taint[] {
    return this.taintsOf(expr, env, { ref, req, depth: 0 });
  }

  protected override propertyTaints(taints: Taint[], key: string): Taint[] {
    return member(taints as XssTaint[], key);
  }

  protected override onDeclaration(decl: VariableDeclaration, env: Env, ref: FunctionRef, req?: Req): void {
    const init = decl.getInitializer();
    if (!init) return;
    const stmt = decl.getFirstAncestorByKind(SyntaxKind.VariableStatement) ?? decl;
    const kind = this.isStringBuild(init) ? "build" : "propagate";
    const here = (h: Hop | undefined) => h?.file === ref.file && h.line === stmt.getStartLineNumber();
    // A source read in this very statement already carries its hop here; anything flowing in gets one.
    const taints = this.taintsOf(init, env, { ref, req, depth: 0 }).map((t) =>
      here(t.hops.at(-1)) ? t : { ...t, hops: [...t.hops, this.hop(stmt, kind, ref)] },
    );
    bindNames(decl.getNameNode(), taints, env);
  }

  /** SQL execution is another analysis's sink; SQL writes are handled where the parameters are visible. */
  protected override recordSink(): void {}

  override analyze(fn: Fn, env: Env, depth: number, req?: Req, self?: Value): void {
    const entered: Hop[] = this.pendingCall
      ? [this.pendingCall, this.paramHop(fn, "called")]
      : depth === 0 && this.currentRoute
        ? [{ ...this.paramHop(fn, `handles ${this.currentRoute}`), kind: "entry" }]
        : [];
    this.pendingCall = undefined;
    this.analyzed++;
    if (depth === 0 && !this.inBrowser) this.walking = { fn, req: req?.name };
    this.chain.push(...entered);
    try {
      super.analyze(fn, env, depth, req, self);
    } finally {
      this.chain.splice(this.chain.length - entered.length, entered.length);
    }
  }

  protected override onCall(call: CallExpression, env: Env, ref: FunctionRef, depth: number, req?: Req): void {
    if (this.inBrowser && this.stateDeclaration(unwrap(call.getExpression()), 1)) return; // a state setter: see onStateSetter
    const callHop = this.hop(call, "call", ref);
    const before = this.analyzed;
    this.pendingCall = callHop;
    super.onCall(call, env, ref, depth, req);
    if (this.followAll && this.analyzed === before) {
      // No tainted argument: the callee may still read stored data and render it.
      const callee = this.resolveCallee(call);
      if (callee.kind === "function") {
        this.pendingCall = callHop;
        this.analyze(callee.fn, new Map(), depth + 1, undefined, callee.self);
      }
    }
    this.pendingCall = undefined;
    this.followCallbacks(call, env, ref, depth, req, callHop);
  }

  /**
   * Inline callbacks (`items.map((x) => …)`, `.then(…)`) run with the enclosing scope: they are walked with its
   * variables, and an element callback's first parameter takes the taint of the array it iterates.
   */
  private followCallbacks(call: CallExpression, env: Env, ref: FunctionRef, depth: number, req: Req | undefined, callHop: Hop): void {
    const callee = unwrap(call.getExpression());
    const iterated = Node.isPropertyAccessExpression(callee) && ELEMENT_CALLBACKS.has(callee.getName()) ? callee.getExpression() : undefined;
    const items = iterated ? this.taintsOf(iterated, env, { ref, req, depth: 0 }) : [];
    for (const arg of call.getArguments()) {
      const fn = unwrap(arg);
      if (!isFn(fn) || (items.length === 0 && !this.followAll && !this.closesOverTaint(fn, env))) continue;
      const first = fn.getParameters()[0]?.getNameNode();
      const shadowed = new Map<string, Taint[] | undefined>();
      if (first && items.length > 0) {
        const bound = new Map<string, Taint[]>();
        const hops = [callHop, this.paramHop(fn, `param ${first.getText()}`)];
        bindNames(first, items.map((t) => ({ ...t, hops: [...t.hops, ...hops] })), bound);
        for (const [n, t] of bound) {
          shadowed.set(n, env.get(n));
          env.set(n, t);
        }
      }
      this.pendingCall = callHop;
      this.analyze(fn, env, depth + 1, req);
      for (const [n, t] of shadowed) (t ? env.set(n, t) : env.delete(n));
    }
  }

  private closesOverTaint(fn: Fn, env: Env): boolean {
    return fn.getDescendantsOfKind(SyntaxKind.Identifier).some((id) => env.has(id.getText()));
  }

  protected override visitNode(node: Node, env: Env, ref: FunctionRef, req?: Req): void {
    const scope: Scope = { ref, req, depth: 0 };
    if (this.inBrowser) return this.visitBrowserNode(node, env, scope);
    if (Node.isTemplateExpression(node)) {
      const literals = [node.getHead().getLiteralText(), ...node.getTemplateSpans().map((s) => s.getLiteral().getLiteralText())];
      this.onOutput(literals, node.getTemplateSpans().map((s) => s.getExpression()), env, scope);
    } else if (isChainTop(node)) {
      const operands = plusOperands(node);
      const literals = operands.map(literalText).filter((t): t is string => t !== undefined);
      this.onOutput(literals, operands.filter((o) => literalText(o) === undefined), env, scope);
    } else if (Node.isCallExpression(node)) {
      this.onResponseWrite(node, env, scope);
      if (this.resolveCallee(node).kind === "sink") this.onSqlWrite(node, env, scope);
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

  /** The response object a call writes through: `res.send(x)`, `res.status(200).json(x)` → `res`. */
  private responseCall(call: CallExpression): string | undefined {
    const callee = unwrap(call.getExpression());
    if (!Node.isPropertyAccessExpression(callee)) return undefined;
    let root: Node = callee.getExpression();
    while (Node.isCallExpression(root) || Node.isPropertyAccessExpression(root)) root = unwrap(root.getExpression());
    return Node.isIdentifier(root) && RESPONSE_OBJECT.test(root.getText()) ? callee.getName() : undefined;
  }

  /**
   * `res.send(x)` with raw input: written to the response as-is (Express sends strings as HTML). An object is sent as
   * JSON — not an HTML output, but when it carries a stored value, that value is what browser code can fetch.
   */
  private onResponseWrite(call: CallExpression, env: Env, scope: Scope): void {
    const method = this.responseCall(call);
    const [body] = call.getArguments();
    if (!method || !body) return;
    const json = method === "json" || Node.isObjectLiteralExpression(unwrap(body)) || Node.isArrayLiteralExpression(unwrap(body));
    for (const t of this.taintsOf(body, env, scope)) {
      if (json && t.stored && !this.exposures.has(t.stored)) {
        const hop = this.hop(call, "propagate", scope.ref!, `${excerpt(call)}  [sent as JSON${this.currentRoute ? ` by ${this.currentRoute}` : ""}]`);
        this.exposures.set(t.stored, { ...t, hops: [...t.hops, hop], route: this.currentRoute ?? t.route, reach: this.currentReach() });
      } else if (!json && RESPONSE_WRITES.has(method) && stateOf(t) !== "html") {
        this.record(t, body, "response", scope.ref!);
      }
    }
  }

  /** A SQL write whose parameter for a column is raw request input: that column now holds attacker-controlled text. */
  private onSqlWrite(call: CallExpression, env: Env, scope: Scope): void {
    const [text, params] = call.getArguments();
    const sql = text && this.sqlTextOf(text);
    const write = sql ? sqlWrite(sql) : undefined;
    if (!write || !params) return;
    const p = unwrap(params);
    for (const [column, i] of write.columns) {
      const value = Node.isArrayLiteralExpression(p) ? p.getElements()[i] : undefined;
      if (!value) continue;
      const key = `${write.table}.${column}`;
      const raw = this.taintsOf(value, env, scope).find((t) => stateOf(t) === "text" && !t.field && !t.stored);
      if (!raw || this.storedWrites.has(key)) continue;
      const hop = this.hop(call, "store", scope.ref!, `${excerpt(call)}  [stores ${key}]`);
      this.storedWrites.set(key, { origin: raw.origin, hops: [...raw.hops, hop], route: this.currentRoute });
    }
  }

  /** The SQL text of a query argument: a literal, a `+` chain of literals, or a constant holding one. */
  private sqlTextOf(node: Node, depth = 0): string | undefined {
    const e = unwrap(node);
    const literal = literalText(e);
    if (literal !== undefined) return literal;
    if (Node.isTemplateExpression(e)) return [e.getHead().getLiteralText(), ...e.getTemplateSpans().map((s) => `?${s.getLiteral().getLiteralText()}`)].join("");
    if (isPlus(e)) {
      const parts = plusOperands(e).map((o) => this.sqlTextOf(o, depth + 1));
      return parts.every((t) => t !== undefined) ? parts.join("") : undefined;
    }
    if (Node.isIdentifier(e) && depth < 3) {
      const decl = this.lookup(e, e.getText());
      const init = Node.isVariableDeclaration(decl) ? decl.getInitializer() : undefined;
      return init ? this.sqlTextOf(init, depth + 1) : undefined;
    }
    return undefined;
  }

  /** Rows read by a SQL call that include stored columns: each carries that column's taint as a field. */
  private storedReads(call: CallExpression): XssTaint[] {
    const [text] = call.getArguments();
    const sql = text && this.sqlTextOf(text);
    const read = sql ? sqlRead(sql) : undefined;
    if (!read) return [];
    const out: XssTaint[] = [];
    for (const [key, write] of this.storedWrites) {
      const [table, column] = key.split(".");
      if (table !== read.table || !(read.columns.includes(column) || read.columns.includes("*"))) continue;
      const load: Hop = { ...this.hop(call, "load", this.enclosingRef(call), `${excerpt(call)}  [reads ${key}]`) };
      out.push({ origin: `stored:${key}`, hops: [...write.hops, ...this.chain, load], state: "text", field: column, stored: key, route: this.currentRoute });
    }
    return out;
  }

  private enclosingRef(node: Node): FunctionRef {
    const fn = node.getFirstAncestor(isFn);
    return fn ? this.functionRef(fn) : { file: this.relPath(node.getSourceFile()), name: "<module>", startLine: 1, endLine: 1, code: "" };
  }

  private paramHop(fn: Fn, note: string): Hop {
    return { file: this.relPath(fn.getSourceFile()), line: fn.getStartLineNumber(), code: `${this.signature(fn)}  [${note}]`, kind: "param", fn: this.functionRef(fn) };
  }

  private record(t: XssTaint, value: Node, context: XssContext, ref: FunctionRef, encoder?: string): void {
    if (t.field) return; // a record whose stored property was not selected: the record itself is not that text
    const sf = value.getSourceFile();
    const line = value.getStartLineNumber();
    const code = sf.getFullText().split(/\r?\n/)[line - 1].trim();
    const sink: Hop = { file: this.relPath(sf), line, code: code.length > 140 ? `${code.slice(0, 139)}…` : code, kind: "sink", fn: ref };
    const encoded = encoder !== undefined || stateOf(t) === "encoded";
    const key = `${t.origin}->${sink.file}:${sink.line}:${encoded}`;
    if (this.xssKeys.has(key)) return;
    this.xssKeys.add(key);
    const route = this.currentRoute ?? t.route;
    const writtenBy = t.stored ? this.storedWrites.get(t.stored)?.route : undefined;
    const by = encoder ?? (encoded ? t.encoder : undefined);
    const reach = t.stored ? (this.inBrowser ? t.reach : this.currentReach()) : undefined;
    this.xssPaths.push({
      hops: [...t.hops, sink],
      origin: t.origin,
      ...(route ? { route } : {}),
      context,
      encoded,
      ...(by ? { encoder: by } : {}),
      sinkImports: imports(sf),
      ...(t.stored ? { stored: t.stored } : {}),
      ...(writtenBy ? { writtenBy } : {}),
      ...(reach ? { reach } : {}),
    });
  }

  /** The reach of the handler being walked: who receives what it renders or sends. */
  private currentReach(): Reach | undefined {
    const handler = this.walking;
    if (!handler) return undefined;
    let reach = this.reaches.get(handler.fn);
    if (!reach) {
      reach = reachOf(handler.fn, handler.req, this.relPath(handler.fn.getSourceFile()));
      if (this.currentRoute) reach.route = this.currentRoute;
      this.reaches.set(handler.fn, reach);
    }
    return reach;
  }

  // ---- browser code -------------------------------------------------------------------------------

  /** True for files of a package that depends on a UI library (nearest package.json). */
  isBrowserFile(sf: SourceFile): boolean {
    for (let dir = path.dirname(sf.getFilePath()); ; dir = path.dirname(dir)) {
      const cached = this.browserFiles.get(dir);
      if (cached !== undefined) return cached;
      const pkg = path.join(dir, "package.json");
      if (existsSync(pkg)) {
        let ui = false;
        try {
          const json = JSON.parse(readFileSync(pkg, "utf8"));
          const deps = { ...json.dependencies, ...json.devDependencies, ...json.peerDependencies };
          ui = UI_PACKAGES.some((p) => p in deps);
        } catch {
          ui = false;
        }
        this.browserFiles.set(dir, ui);
        return ui;
      }
      if (path.dirname(dir) === dir) return false;
    }
  }

  /**
   * Walks browser code: every function of every browser file is an entry (components, event handlers), with the
   * server's JSON responses as the source. Two rounds, so state set in a handler reaches the render that reads it.
   */
  traceBrowser(files: SourceFile[]): void {
    const browser = files.filter((f) => this.isBrowserFile(f));
    if (browser.length === 0 || this.exposures.size === 0) return;
    this.inBrowser = true;
    this.setCurrentRoute(undefined);
    try {
      for (let round = 0; round < 2; round++) {
        for (const sf of browser) {
          for (const fn of sf.getDescendants().filter(isFn)) this.analyze(fn, new Map(), 0);
        }
      }
    } finally {
      this.inBrowser = false;
    }
  }

  private visitBrowserNode(node: Node, env: Env, scope: Scope): void {
    const ref = scope.ref!;
    if (Node.isJsxAttribute(node) && node.getNameNode().getText() === "dangerouslySetInnerHTML") {
      const init = node.getInitializer();
      const obj = Node.isJsxExpression(init) ? init.getExpression() : undefined;
      const html = Node.isObjectLiteralExpression(obj) ? obj.getProperty("__html") : undefined;
      const value = Node.isPropertyAssignment(html) ? html.getInitializerOrThrow() : undefined;
      if (value) for (const t of this.taintsOf(value, env, scope)) this.record(t, value, "dom-html", ref);
    } else if (Node.isJsxExpression(node) && Node.isJsxElement(node.getParent()) && node.getExpression()) {
      // A JSX child expression is rendered as text: React escapes it.
      const value = node.getExpression()!;
      for (const t of this.taintsOf(value, env, scope)) {
        if (stateOf(t) !== "encoded") this.record(t, value, "jsx-text", ref, "rendered as a JSX text child (React escapes it)");
      }
    } else if (Node.isJsxSelfClosingElement(node) || Node.isJsxOpeningElement(node)) {
      this.onComponent(node, env, scope);
    } else if (Node.isBinaryExpression(node) && node.getOperatorToken().getKind() === SyntaxKind.EqualsToken) {
      const left = node.getLeft();
      if (Node.isPropertyAccessExpression(left) && DOM_HTML_PROPS.has(left.getName())) {
        for (const t of this.taintsOf(node.getRight(), env, scope)) this.record(t, node.getRight(), "dom-html", ref);
      }
    } else if (Node.isCallExpression(node)) {
      const callee = unwrap(node.getExpression());
      const name = Node.isPropertyAccessExpression(callee) ? callee.getName() : undefined;
      const value = name === "insertAdjacentHTML" ? node.getArguments()[1] : name && DOM_HTML_METHODS.has(name) ? node.getArguments()[0] : undefined;
      if (value) for (const t of this.taintsOf(value, env, scope)) this.record(t, value, "dom-html", ref);
      this.onStateSetter(node, env, scope);
    }
  }

  /** `<Child prop={value} />`: walks the child component with its props bound to the attribute values. */
  private onComponent(node: Node, env: Env, scope: Scope): void {
    if (!Node.isJsxSelfClosingElement(node) && !Node.isJsxOpeningElement(node)) return;
    const tag = node.getTagNameNode();
    if (!/^[A-Z]/.test(tag.getText().split(".").pop()!)) return; // lower-case tags are DOM elements
    const target = this.resolveFunction(tag);
    if (!target) return;
    const props = new Map<string, XssTaint[]>();
    let spread: XssTaint[] = [];
    for (const attr of node.getAttributes()) {
      if (Node.isJsxSpreadAttribute(attr)) spread = merge(spread, this.taintsOf(attr.getExpression(), env, scope));
      else if (Node.isJsxAttribute(attr)) {
        const init = attr.getInitializer();
        const expr = Node.isJsxExpression(init) ? init.getExpression() : undefined;
        if (expr && !isFn(unwrap(expr))) props.set(attr.getNameNode().getText(), this.taintsOf(expr, env, scope));
      }
    }
    if (spread.length === 0 && [...props.values()].every((t) => t.length === 0)) return;
    const hops = [this.hop(node, "call", scope.ref!), this.paramHop(target.fn, "props")];
    const withHops = (ts: XssTaint[]) => ts.map((t) => ({ ...t, hops: [...t.hops, ...hops] }));
    const childEnv: Env = new Map();
    const first = target.fn.getParameters()[0]?.getNameNode();
    if (Node.isIdentifier(first)) childEnv.set(first.getText(), withHops(merge(spread, ...props.values())));
    else if (Node.isObjectBindingPattern(first)) {
      for (const el of first.getElements()) {
        const key = (el.getPropertyNameNode() ?? el.getNameNode()).getText();
        const taints = withHops(merge(spread, props.get(key) ?? []));
        if (taints.length > 0) bindNames(el.getNameNode(), taints, childEnv);
      }
    }
    this.pendingCall = hops[0];
    this.analyze(target.fn, childEnv, 1, undefined, target.self);
  }

  /** `setX(value)` for `const [x, setX] = useState(…)`: the state `x` now carries `value`'s taint. */
  private onStateSetter(call: CallExpression, env: Env, scope: Scope): void {
    const callee = unwrap(call.getExpression());
    const [arg] = call.getArguments();
    if (!Node.isIdentifier(callee) || !arg || isFn(unwrap(arg))) return;
    const state = this.stateDeclaration(callee, 1);
    if (!state) return;
    const taints = this.taintsOf(arg, env, scope);
    if (taints.length === 0) return;
    const hop = this.hop(call, "propagate", scope.ref!, `${excerpt(call)}  [state ${state.name}]`);
    const prev = this.stateTaints.get(state.decl) ?? [];
    this.stateTaints.set(state.decl, merge(prev, taints.map((t) => ({ ...t, hops: [...t.hops, hop] }))));
  }

  /** The `useState` declaration an identifier is element `index` of (0 = value, 1 = setter). */
  private stateDeclaration(id: Node, index: number): { decl: Node; name: string } | undefined {
    if (!Node.isIdentifier(id)) return undefined;
    const el = this.lookup(id, id.getText());
    const pattern = el?.getParent();
    const decl = pattern?.getParent();
    if (!Node.isBindingElement(el) || !Node.isArrayBindingPattern(pattern) || !Node.isVariableDeclaration(decl)) return undefined;
    const init = decl.getInitializer();
    const call = init && unwrap(init);
    if (!Node.isCallExpression(call) || !/(?:^|\.)useState$/.test(call.getExpression().getText())) return undefined;
    if (pattern.getElements().indexOf(el) !== index) return undefined;
    const value = pattern.getElements()[0];
    return { decl, name: Node.isBindingElement(value) ? value.getName() : "state" };
  }

  // ---- classification of an expression's taint ------------------------------------------------

  private taintsOf(node: Node, env: Env, scope: Scope): XssTaint[] {
    const e = unwrap(node);
    if (Node.isIdentifier(e)) {
      const own = env.get(e.getText()) as XssTaint[] | undefined;
      if (own || !this.inBrowser) return own ?? [];
      const state = this.stateDeclaration(e, 0);
      return state ? (this.stateTaints.get(state.decl) ?? []) : [];
    }
    if (Node.isPropertyAccessExpression(e) || Node.isElementAccessExpression(e)) {
      const source = this.sourceRead(e, scope);
      if (source) return [source];
      const name = memberName(e);
      if (name === "length") return [];
      return member(this.taintsOf(e.getExpression(), env, scope), name);
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
    const inner = merge(...values.map((v) => this.taintsOf(v, env, scope))).filter((t) => !t.field);
    return literals.some((t) => MARKUP.test(t)) ? inner.map((t) => ({ ...t, state: "html" as const })) : inner;
  }

  private callTaints(call: CallExpression, env: Env, scope: Scope): XssTaint[] {
    const callee = unwrap(call.getExpression());
    const args = call.getArguments();
    const receiver = Node.isPropertyAccessExpression(callee) || Node.isElementAccessExpression(callee) ? callee.getExpression() : undefined;
    const name = receiver ? memberName(callee) : Node.isIdentifier(callee) ? callee.getText() : undefined;
    const argTaints = () => args.map((a) => (isFn(unwrap(a)) ? [] : this.taintsOf(a, env, scope)));

    const resolved = this.resolveCallee(call);
    if (resolved.kind === "sink") return this.storedReads(call); // database rows: tainted only where stored input is read back
    if (resolved.kind === "function") {
      const fn = resolved.fn;
      const returned = this.summarize(fn, args, argTaints(), env, scope);
      if (!scope.ref) return returned;
      // The value comes back out of the callee: show the call and the callee, so its code is part of the evidence.
      const callHop = this.hop(call, "call", scope.ref);
      return returned.map((t) => {
        const what = stateOf(t) === "text" ? "the value" : `${stateOf(t)} output`;
        return { ...t, hops: [...t.hops, callHop, this.paramHop(fn, `returns ${what}`)] };
      });
    }
    if (this.inBrowser && this.isServerFetch(resolved, name, receiver === undefined)) {
      const load: Hop = this.hop(call, "load", this.enclosingRef(call), `${excerpt(call)}  [response from the server]`);
      return [...this.exposures.values()].map((t) => ({ ...t, hops: [...t.hops, ...this.chain, load] }));
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

  /** `fetch(…)` or an HTTP client package call in browser code: its response is what the server sent. */
  private isServerFetch(v: Value | { kind: "sink" }, name: string | undefined, direct: boolean): boolean {
    if (v.kind !== "external") return false;
    if (/^global 'fetch'$/.test(v.what)) return direct;
    const pkg = /^package '(.+)'$/.exec(v.what)?.[1];
    return pkg !== undefined && HTTP_CLIENTS.has(pkg) && (name === undefined || /^(?:get|post|put|patch|delete|request|fetch|axios|ky)$/.test(name));
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
    if (argTaints.every((t) => t.length === 0) && !this.followAll) return [];
    if (this.summarizing.has(fn) || scope.depth >= SUMMARY_DEPTH) return merge(...argTaints);
    // Summaries are cached by origin and state; the hops are always this caller's own.
    const incoming = new Map(merge(...argTaints).map((t) => [t.origin, t.hops]));
    const ownHops = (ts: XssTaint[]) => ts.map((t) => ({ ...t, hops: incoming.get(t.origin) ?? t.hops }));
    const context = this.followAll ? `|${this.inBrowser}|${this.chain.map((h) => `${h.file}:${h.line}`).join(">")}` : "";
    const key = `${fn.getSourceFile().getFilePath()}:${fn.getStart()}|${argTaints.map((ts) => ts.map((t) => `${t.origin}=${stateOf(t)}${t.field ? `.${t.field}` : ""}`).join(",")).join("|")}${context}`;
    const cached = this.summaries.get(key);
    if (cached) return ownHops(cached);

    const inner: Scope = { depth: scope.depth + 1 };
    const env: Env = new Map();
    fn.getParameters().forEach((param, i) => {
      const taints = param.isRestParameter() ? merge(...argTaints.slice(i)) : (argTaints[i] ?? []);
      const nameNode = param.getNameNode();
      const literal = args[i] ? unwrap(args[i]) : undefined;
      if (!Node.isObjectBindingPattern(nameNode) || !Node.isObjectLiteralExpression(literal)) return bindNames(nameNode, taints, env);
      for (const el of nameNode.getElements()) {
        const key = (el.getPropertyNameNode() ?? el.getNameNode()).getText();
        const prop = literal.getProperty(key);
        const bound = Node.isPropertyAssignment(prop)
          ? this.taintsOf(prop.getInitializerOrThrow(), callerEnv, scope)
          : Node.isShorthandPropertyAssignment(prop)
            ? this.taintsOf(prop.getNameNode(), callerEnv, scope)
            : member(taints, key);
        bindNames(el.getNameNode(), bound, env);
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
          bindNames(node.getNameNode(), this.taintsOf(node.getInitializer()!, env, inner), env);
        } else if (Node.isBinaryExpression(node) && Node.isIdentifier(node.getLeft())) {
          const op = node.getOperatorToken().getKind();
          if (op !== SyntaxKind.EqualsToken && op !== SyntaxKind.PlusEqualsToken) return;
          const name = node.getLeft().getText();
          const right = this.taintsOf(node.getRight(), env, inner);
          const next = op === SyntaxKind.PlusEqualsToken ? merge((env.get(name) ?? []) as XssTaint[], right) : right;
          if (next.length > 0) env.set(name, next);
          else env.delete(name);
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

/**
 * Who receives what a handler renders or sends. An identity read is `<req>.user|session|auth` (or Koa
 * `<ctx>.state.user`); it scopes the response when it is compared with something or passed to a call (a lookup or
 * query constrained by it). No identity read: the route may be reached without signing in.
 */
function reachOf(fn: Fn, req: string | undefined, file: string): Reach {
  const handler = { at: `${file}:${fn.getStartLineNumber()}`, code: excerpt(fn, 80) };
  if (!req) return { level: "public", ...handler };
  const reads = fn.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression).filter((pa) => {
    if (!IDENTITY_PROPS.has(pa.getName())) return false;
    const target = unwrap(pa.getExpression());
    const isReq = (n: Node) => Node.isIdentifier(n) && n.getText() === req;
    return isReq(target) || (Node.isPropertyAccessExpression(target) && target.getName() === "state" && isReq(target.getExpression()));
  });
  if (reads.length === 0) return { level: "public", ...handler };
  const COMPARE = new Set([SyntaxKind.EqualsEqualsEqualsToken, SyntaxKind.ExclamationEqualsEqualsToken, SyntaxKind.EqualsEqualsToken, SyntaxKind.ExclamationEqualsToken]);
  for (const read of reads) {
    const scoping = read.getFirstAncestor(
      (a) => (Node.isBinaryExpression(a) && COMPARE.has(a.getOperatorToken().getKind())) || Node.isCallExpression(a),
    );
    if (scoping && scoping.getFirstAncestor(isFn) === fn) {
      return { level: "own-scope", at: `${file}:${scoping.getStartLineNumber()}`, code: excerpt(scoping, 80) };
    }
  }
  return { level: "authenticated", at: `${file}:${reads[0].getStartLineNumber()}`, code: excerpt(reads[0], 80) };
}

/** Binds a declaration's name(s): an identifier takes the taint; `{ a, b: c }` takes each property's; `[a, b]` the whole. */
function bindNames(nameNode: Node, taints: Taint[], env: Env): void {
  if (Node.isIdentifier(nameNode)) {
    if (taints.length > 0) env.set(nameNode.getText(), taints);
    else env.delete(nameNode.getText());
    return;
  }
  if (Node.isObjectBindingPattern(nameNode)) {
    for (const el of nameNode.getElements()) {
      const key = el.getDotDotDotToken() ? undefined : (el.getPropertyNameNode() ?? el.getNameNode()).getText();
      bindNames(el.getNameNode(), key === undefined ? taints : member(taints as XssTaint[], key), env);
    }
    return;
  }
  if (Node.isArrayBindingPattern(nameNode)) {
    for (const el of nameNode.getElements()) if (Node.isBindingElement(el)) bindNames(el.getNameNode(), taints, env);
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

/**
 * Traces every entry point of a project to HTML output, classifying each output as raw or encoded. A first pass
 * finds which columns request input is written to; the second traces again with reads of those columns as sources,
 * then walks browser code with the server's JSON responses as sources.
 */
export function traceXssProject(dir: string): XssTraceResult {
  const root = path.resolve(dir);
  const writes = new XssTracer(root);
  traceProject(dir, writes);
  const tracer = new XssTracer(root, writes.storedWrites);
  const trace = traceProject(dir, tracer);
  tracer.traceBrowser(discoverFiles(root).map((f) => tracer.load(f)));
  return { ...trace, xss: sortXss(tracer.xssPaths) };
}
