// Stage 1 of access-control analysis: deterministic context assembly per route (no LLM).
// An access-control bug is a missing check, not a dangerous sink, so instead of hunting sinks this collects the
// evidence a reviewer needs: what the request identifies, what identity was available, how the data is scoped,
// which checks exist on this route, and which sibling routes enforce the check.
import path from "node:path";
import { Node, SyntaxKind, type BinaryExpression, type Project, type CallExpression, type SourceFile } from "ts-morph";
import { discoverFiles, discoverSqlFiles } from "../crossfile/files.js";
import { excerpt, isFn, Tracer, type CandidatePath, type Fn, type FunctionRef, type Handler, type Hop } from "../crossfile/trace.js";
import { columnForValue, describeStatement, evaluateSql, readSchema, type SchemaTable, type StatementVerb } from "./sql.js";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "del", "all"]);
/** Request properties authentication middleware conventionally sets: `req.user`, `ctx.state.user`, … */
const IDENTITY_PROPS = ["user", "auth", "account", "principal", "currentUser", "session"];
/** Request fields that identify a record: every path parameter, plus query/body fields named like identifiers. */
const ID_LIKE = /(?:^id$|Id$|_id$|ID$|^uuid$|Uuid$|_uuid$|^key$|Key$|_key$|^slug$|Slug$)/;
const EQUALITY = new Set([
  SyntaxKind.EqualsEqualsEqualsToken,
  SyntaxKind.ExclamationEqualsEqualsToken,
  SyntaxKind.EqualsEqualsToken,
  SyntaxKind.ExclamationEqualsToken,
]);

export type AccessKind = "read" | "write";

/** A request-supplied identifier reaching a data access. */
export interface Access {
  path: CandidatePath;
  /** The request field (or the variable holding it) that selects the record. */
  field: string;
  location: "params" | "query" | "body" | "request";
  kind: AccessKind;
  verb: StatementVerb;
  /** The statement as far as it is static; interpolated values appear as `{{name}}`. */
  sql: string;
  tables: string[];
  /** The column the identifier is compared with or written to, when it can be read from the statement. */
  column?: string;
}

export interface Identity {
  /** e.g. `req.user` */
  expression: string;
  fields: string[];
  /** The middleware that sets it, when found on the route's chain. */
  middleware?: FunctionRef;
  evidence: string;
}

export type GuardKind =
  | "request value compared with identity"
  | "resource owner compared with identity"
  | "query constrained by identity"
  | "identity condition";

/** An authorization check found on a route: handler, a function on its access path, or its middleware. */
export interface Guard {
  kind: GuardKind;
  file: string;
  line: number;
  code: string;
  fn: FunctionRef;
}

export type RouteStatus = "candidate" | "guarded" | "unscoped" | "public" | "no-identifier";

export interface AccessRoute {
  method: string;
  path: string;
  handler: FunctionRef;
  registeredAt: string;
  middleware: FunctionRef[];
  status: RouteStatus;
  reason: string;
  /** Request identifiers reaching data accesses; for a candidate, the ones no check covers. */
  accesses: Access[];
  identity?: Identity;
  guards: Guard[];
  /** Tables any of the route's traced data accesses touch (identifier or not). */
  tables: string[];
  /** Handler plus every function on its access paths: the code the judge reads. */
  functions: FunctionRef[];
}

export interface AccessContext {
  root: string;
  files: number;
  schemaFiles: string[];
  schema: SchemaTable[];
  routes: AccessRoute[];
}

interface Mount {
  prefix: string;
  middleware: Fn[];
  parent: SourceFile;
}

/** Identity-derived and request-derived names in one function. */
interface Names {
  identity: Set<string>;
  request: Set<string>;
}

const snake = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();

/** Columns that would tie a row to the caller, mapped to the identity field: `tenantId` → `tenant_id`; `id` → `user_id` / `owner_id`. */
export function ownerColumns(identity: Identity | undefined): Map<string, string> {
  const cols = new Map<string, string>();
  for (const f of identity?.fields ?? []) {
    if (f === "id") ["user_id", "owner_id"].forEach((c) => cols.set(c, f));
    else cols.set(snake(f), f);
  }
  return cols;
}

/** Scope records: tables that owner columns reference (`tenant_id REFERENCES tenants(id)` → tenants). */
export function scopeTables(schema: SchemaTable[], owners: Map<string, string>): Map<string, { field: string; referencedBy: string[] }> {
  const out = new Map<string, { field: string; referencedBy: string[] }>();
  for (const t of schema) {
    for (const c of t.columns) {
      const field = owners.get(c.name);
      if (!field || !c.references) continue;
      const entry = out.get(c.references.table) ?? { field, referencedBy: [] };
      entry.referencedBy.push(`${t.name}.${c.name}`);
      out.set(c.references.table, entry);
    }
  }
  return out;
}

function terminates(stmt: Node): boolean {
  const nodes = [stmt, ...stmt.getDescendants()].filter((n) => !n.getFirstAncestor((a) => isFn(a) && stmt.containsRange(a.getPos(), a.getEnd())));
  return nodes.some(
    (n) =>
      Node.isReturnStatement(n) ||
      Node.isThrowStatement(n) ||
      (Node.isCallExpression(n) && /^(?:next|res\.(?:status|sendStatus)|ctx\.throw)\b/.test(n.getExpression().getText())),
  );
}

class AccessAnalyzer {
  private readonly tracer: Tracer;
  private readonly mounts = new Map<SourceFile, Mount[]>();
  private schema: SchemaTable[] = [];

  constructor(readonly root: string, project?: Project) {
    this.tracer = new Tracer(root, project);
  }

  run(): AccessContext {
    const files = discoverFiles(this.root).map((f) => this.tracer.load(f));
    const schemaFiles = discoverSqlFiles(this.root).map((abs) => ({ abs, rel: path.relative(this.root, abs) }));
    this.schema = readSchema(schemaFiles);
    this.collectMounts(files);

    // The route's handler is the last function of its registration; earlier ones are route-level middleware.
    const handlers = this.tracer.registeredHandlers(files).filter((h) => {
      if (!h.registration || !HTTP_METHODS.has(this.methodOf(h.registration))) return false;
      const fns = h.registration.getArguments().map((a) => this.tracer.resolveFunction(a)?.fn).filter((f) => f !== undefined);
      return fns.at(-1) === h.fn;
    });
    const projectFields = this.identityFieldsRead(files);
    const routes = handlers.map((h) => this.route(h, projectFields));
    return { root: this.root, files: files.length, schemaFiles: schemaFiles.map((f) => f.rel), schema: this.schema, routes };
  }

  // ---- routing: mounts, middleware chains, full paths ------------------------------------------

  private methodOf(call: CallExpression): string {
    const callee = call.getExpression();
    return Node.isPropertyAccessExpression(callee) ? callee.getName() : "";
  }

  private literal(node: Node | undefined): string | undefined {
    return node && (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) ? node.getLiteralValue() : undefined;
  }

  /** `x.use(fn)` with no path, on the same receiver, registered before `call` in the same file. */
  private useBefore(call: CallExpression): Fn[] {
    const callee = call.getExpression();
    if (!Node.isPropertyAccessExpression(callee)) return [];
    const receiver = callee.getExpression().getText();
    const out: Fn[] = [];
    for (const c of call.getSourceFile().getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (c.getStart() >= call.getStart()) break;
      const e = c.getExpression();
      if (!Node.isPropertyAccessExpression(e) || e.getName() !== "use" || e.getExpression().getText() !== receiver) continue;
      if (this.literal(c.getArguments()[0]) !== undefined) continue;
      for (const arg of c.getArguments()) {
        if (this.tracer.requiredFile(arg)) continue;
        const f = this.tracer.resolveFunction(arg);
        if (f) out.push(f.fn);
      }
    }
    return out;
  }

  /** `app.use('/prefix', mw…, require('./routes/x'))`: which middleware and prefix apply to a router file. */
  private collectMounts(files: SourceFile[]): void {
    for (const sf of files) {
      for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (this.methodOf(call) !== "use") continue;
        const args = call.getArguments();
        const prefix = this.literal(args[0]) ?? "";
        const middleware: Fn[] = [...this.useBefore(call)];
        for (const arg of args) {
          const file = this.tracer.requiredFile(arg);
          if (file) {
            if (!this.mounts.has(file)) this.mounts.set(file, []);
            this.mounts.get(file)!.push({ prefix, middleware: [...middleware], parent: sf });
            continue;
          }
          const f = this.tracer.resolveFunction(arg);
          if (f) middleware.push(f.fn);
        }
      }
    }
  }

  /** Prefix and middleware a file inherits from where it is mounted (first mount, followed upward). */
  private mountChain(file: SourceFile, depth = 0): { prefix: string; middleware: Fn[] } {
    const mount = this.mounts.get(file)?.[0];
    if (!mount || depth > 8) return { prefix: "", middleware: [] };
    const parent = this.mountChain(mount.parent, depth + 1);
    return { prefix: parent.prefix + mount.prefix, middleware: [...parent.middleware, ...mount.middleware] };
  }

  // ---- one route ---------------------------------------------------------------------------------

  private route(h: Handler, projectFields: string[]): AccessRoute {
    const call = h.registration!;
    const sf = call.getSourceFile();
    const mount = this.mountChain(sf);
    const routeLevel = call
      .getArguments()
      .map((a) => this.tracer.resolveFunction(a)?.fn)
      .filter((f): f is Fn => f !== undefined && f !== h.fn);
    const chain = [...mount.middleware, ...this.useBefore(call), ...routeLevel];
    const routePath = (mount.prefix + (this.literal(call.getArguments()[0]) ?? "")).replace(/\/{2,}/g, "/").replace(/(.)\/$/, "$1") || "/";

    const before = this.tracer.paths.length;
    this.tracer.analyze(h.fn, new Map(), 0, h.req, h.self);
    const paths = this.tracer.paths.slice(before);

    const identity = this.identity(chain, h, projectFields);
    const accesses = this.dedupeAccesses(paths.flatMap((p) => this.accesses(p)));
    const tables = [...new Set(paths.flatMap((p) => this.statementAt(p)?.tables ?? []))];
    const names = this.namesAlongPaths(h, paths);
    const guards = [...this.guardsIn(names), ...this.middlewareGuards(chain), ...this.queryGuards(paths, names)];
    const uncovered = accesses.filter((a) => !guards.some((g) => this.covers(g, a, names)));

    const functions = new Map<string, FunctionRef>();
    for (const ref of [this.tracer.functionRef(h.fn), ...paths.flatMap((p) => p.hops.map((hop) => hop.fn))]) functions.set(`${ref.file}:${ref.startLine}`, ref);

    const base = {
      method: this.methodOf(call).toUpperCase(),
      path: routePath,
      handler: this.tracer.functionRef(h.fn),
      registeredAt: `${this.tracer.relPath(sf)}:${call.getStartLineNumber()}`,
      middleware: chain.map((f) => this.tracer.functionRef(f)),
      identity,
      guards,
      tables,
      functions: [...functions.values()],
    };
    if (!identity) {
      return { ...base, status: "public", reason: "no middleware on this route sets an authenticated identity, and the handler reads none", accesses };
    }
    if (accesses.length === 0) {
      return guards.length > 0
        ? { ...base, status: "guarded", reason: "the route checks the caller's identity", accesses }
        : { ...base, status: "no-identifier", reason: "no request-supplied identifier reaches a data access", accesses };
    }
    if (uncovered.length === 0) return { ...base, status: "guarded", reason: "every identifier-driven data access is covered by an identity check", accesses };
    if (this.allUnscoped(uncovered, identity)) {
      return { ...base, status: "unscoped", reason: "the schema gives the accessed tables no ownership column, and they are not scope records", accesses: uncovered };
    }
    return { ...base, status: "candidate", reason: "an identifier-driven data access has no identity check on its path", accesses: uncovered };
  }

  /** True only when the schema describes every accessed table and none is owned or a scope record (public data). */
  private allUnscoped(accesses: Access[], identity: Identity): boolean {
    if (this.schema.length === 0) return false;
    const owners = ownerColumns(identity);
    const scopes = scopeTables(this.schema, owners);
    return accesses.every((a) =>
      a.tables.length > 0 &&
      a.tables.every((t) => {
        const table = this.schema.find((s) => s.name === t);
        return table !== undefined && !scopes.has(t) && !table.columns.some((c) => owners.has(c.name));
      }),
    );
  }

  // ---- identity ----------------------------------------------------------------------------------

  /** `req.user.<field>` / `ctx.state.user.<field>` reads anywhere in the project: the identity fields in use. */
  private identityFieldsRead(files: SourceFile[]): string[] {
    const fields = new Set<string>();
    const re = new RegExp(`^\\w+(?:\\.state)?\\.(?:${IDENTITY_PROPS.join("|")})\\.(\\w+)$`);
    for (const sf of files) {
      for (const pa of sf.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
        const m = re.exec(pa.getText().replace(/\s+/g, ""));
        if (m && /^(?:req|request|ctx|context)$/.test(pa.getText().split(".")[0])) fields.add(m[1]);
      }
    }
    return [...fields];
  }

  private identity(chain: Fn[], h: Handler, projectFields: string[]): Identity | undefined {
    for (const mw of chain) {
      const p = mw.getParameters()[0]?.getName();
      if (!p) continue;
      for (const bin of mw.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
        if (bin.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
        const m = new RegExp(`^${p}\\.(?:state\\.)?(${IDENTITY_PROPS.join("|")})$`).exec(bin.getLeft().getText());
        if (!m) continue;
        const own = this.objectKeys(bin.getRight(), mw);
        const fields = [...new Set([...own, ...projectFields])];
        const ref = this.tracer.functionRef(mw);
        return {
          expression: `${h.req.name}.${bin.getLeft().getText().slice(p.length + 1)}`,
          fields,
          middleware: ref,
          evidence: `${ref.name} (${ref.file}:${bin.getStartLineNumber()}) sets ${bin.getLeft().getText()} = ${excerpt(bin.getRight(), 60)} before this route runs`,
        };
      }
    }
    if (this.mentionsIdentityAccess(h.fn, h.req.name)) {
      return {
        expression: `${h.req.name}.user`,
        fields: projectFields,
        evidence: `the handler reads ${h.req.name}.user, but no middleware setting it was found on the route's chain`,
      };
    }
    return undefined;
  }

  /** Keys of an object literal, or of the object returned by the function whose result an identifier holds. */
  private objectKeys(expr: Node, within: Fn): string[] {
    let e: Node | undefined = expr;
    if (Node.isIdentifier(e)) {
      const name = e.getText();
      e = within.getDescendantsOfKind(SyntaxKind.VariableDeclaration).find((d) => d.getName() === name)?.getInitializer();
    }
    if (Node.isAwaitExpression(e)) e = e.getExpression();
    if (Node.isObjectLiteralExpression(e)) return e.getProperties().flatMap((p) => (Node.isPropertyAssignment(p) || Node.isShorthandPropertyAssignment(p) ? [p.getName()] : []));
    if (Node.isCallExpression(e)) {
      const fn = this.tracer.resolveFunction(e.getExpression())?.fn;
      if (!fn) return [];
      return fn
        .getDescendantsOfKind(SyntaxKind.ReturnStatement)
        .map((r) => r.getExpression())
        .filter(Node.isObjectLiteralExpression)
        .flatMap((o) => o.getProperties().flatMap((p) => (Node.isPropertyAssignment(p) || Node.isShorthandPropertyAssignment(p) ? [p.getName()] : [])));
    }
    return [];
  }

  private isIdentityAccess(node: Node, req: string | undefined): boolean {
    if (!req || !Node.isPropertyAccessExpression(node)) return false;
    return new RegExp(`^${req}\\.(?:state\\.)?(?:${IDENTITY_PROPS.join("|")})\\b`).test(node.getText().replace(/\s+/g, ""));
  }

  private mentionsIdentityAccess(node: Node, req: string): boolean {
    return node.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression).some((pa) => this.isIdentityAccess(pa, req));
  }

  private mentions(node: Node, names: Set<string>, roots: (n: Node) => boolean): boolean {
    return [node, ...node.getDescendants()].some((n) => {
      if (roots(n)) return true;
      if (!Node.isIdentifier(n) || !names.has(n.getText())) return false;
      const parent = n.getParent();
      return !(Node.isPropertyAccessExpression(parent) && parent.getNameNode() === n);
    });
  }

  private mentionsIdentity(node: Node, names: Names, req: string | undefined): boolean {
    return this.mentions(node, names.identity, (n) => this.isIdentityAccess(n, req));
  }

  private mentionsRequest(node: Node, names: Names, req: string | undefined): boolean {
    const re = req ? new RegExp(`^${req}\\.(?:request\\.)?(?:params|query|body)\\b`) : undefined;
    return this.mentions(node, names.request, (n) => Node.isPropertyAccessExpression(n) && !!re?.test(n.getText().replace(/\s+/g, "")));
  }

  // ---- identity / request names along access paths ----------------------------------------------

  private fnAt(ref: FunctionRef): Fn | undefined {
    const sf = this.tracer.load(path.join(this.root, ref.file));
    return sf.getDescendants().find((n): n is Fn => isFn(n) && n.getStartLineNumber() === ref.startLine && n.getEndLineNumber() === ref.endLine);
  }

  private callAt(fn: Fn, hop: Hop): CallExpression | undefined {
    return fn
      .getDescendantsOfKind(SyntaxKind.CallExpression)
      .find((c) => c.getStartLineNumber() === hop.line && excerpt(c) === hop.code);
  }

  /** Local declarations that copy identity or request values extend the seed names (in source order). */
  private propagate(fn: Fn, seed: Names, req: string | undefined): Names {
    const names: Names = { identity: new Set(seed.identity), request: new Set(seed.request) };
    for (const decl of fn.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      if (decl.getFirstAncestor(isFn) !== fn) continue;
      const init = decl.getInitializer();
      if (!init) continue;
      const nameNode = decl.getNameNode();
      const declared = Node.isIdentifier(nameNode) ? [nameNode.getText()] : nameNode.getDescendantsOfKind(SyntaxKind.BindingElement).map((b) => b.getName());
      const fromRequest = this.mentionsRequest(init, names, req);
      const fromIdentity = this.mentionsIdentity(init, names, req);
      for (const n of declared) {
        if (fromRequest) names.request.add(n);
        else if (fromIdentity) names.identity.add(n); // mixed values (e.g. `a || req.user.x`) are request-controlled
      }
    }
    return names;
  }

  /**
   * Identity and request names in the handler and in every function on its access paths: an argument that
   * carries only identity makes the callee's parameter identity; one that carries request input makes it request.
   */
  private namesAlongPaths(h: Handler, paths: CandidatePath[]): Map<Fn, { names: Names; req?: string }> {
    const out = new Map<Fn, { names: Names; req?: string }>();
    out.set(h.fn, { names: this.propagate(h.fn, { identity: new Set(), request: new Set() }, h.req.name), req: h.req.name });
    for (const p of paths) {
      let caller: Fn | undefined = h.fn;
      p.hops.forEach((hop, i) => {
        const next = p.hops[i + 1];
        if (hop.kind !== "call" || next?.kind !== "param" || !caller) return;
        const callee = this.fnAt(next.fn);
        const call = this.callAt(caller, hop);
        const from = out.get(caller) ?? { names: { identity: new Set<string>(), request: new Set<string>() } };
        if (!callee || !call) return;
        const seed: Names = out.get(callee)?.names ?? { identity: new Set(), request: new Set() };
        const params = callee.getParameters();
        call.getArguments().forEach((arg, a) => {
          const name = params[a]?.getNameNode();
          if (!name || !Node.isIdentifier(name)) return;
          if (this.mentionsRequest(arg, from.names, from.req)) seed.request.add(name.getText());
          else if (this.mentionsIdentity(arg, from.names, from.req)) seed.identity.add(name.getText());
        });
        const forwarded = next.code.match(/\[param (\w+) = request\]$/)?.[1];
        out.set(callee, { names: this.propagate(callee, seed, forwarded ?? out.get(callee)?.req), req: forwarded ?? out.get(callee)?.req });
        caller = callee;
      });
    }
    return out;
  }

  // ---- checks --------------------------------------------------------------------------------------

  private guard(kind: GuardKind, node: Node, fn: Fn): Guard {
    return { kind, file: this.tracer.relPath(node.getSourceFile()), line: node.getStartLineNumber(), code: excerpt(node, 160), fn: this.tracer.functionRef(fn) };
  }

  /**
   * `if (<x> !== <identity>) return/throw/reject …` in the handler or a function on its access paths. What `<x>`
   * is decides the kind: the request value itself, a field of a loaded record (its owner), or a constant (a role /
   * flag condition).
   */
  private guardsIn(all: Map<Fn, { names: Names; req?: string }>): Guard[] {
    const guards: Guard[] = [];
    for (const [fn, { names, req }] of all) {
      for (const ifs of fn.getDescendantsOfKind(SyntaxKind.IfStatement)) {
        if (ifs.getFirstAncestor(isFn) !== fn) continue;
        const cond = ifs.getExpression();
        const comparisons = [cond, ...cond.getDescendants()].filter(
          (n): n is BinaryExpression => Node.isBinaryExpression(n) && EQUALITY.has(n.getOperatorToken().getKind()),
        );
        let kind: GuardKind | undefined;
        for (const cmp of comparisons) {
          const [l, r] = [cmp.getLeft(), cmp.getRight()];
          const li = this.mentionsIdentity(l, names, req);
          const ri = this.mentionsIdentity(r, names, req);
          if (li === ri) continue;
          const other = li ? r : l;
          const direct = req ? new RegExp(`^${req}\\.(?:request\\.)?(?:params|query|body)\\b`) : undefined;
          const recordField = Node.isPropertyAccessExpression(other) && !direct?.test(other.getText().replace(/\s+/g, ""));
          if (recordField) kind = "resource owner compared with identity"; // e.g. a loaded record's owner column
          else if (this.mentionsRequest(other, names, req)) kind ??= "request value compared with identity";
          else if (Node.isIdentifier(other) || other.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression).length > 0)
            kind ??= "resource owner compared with identity";
          else kind ??= "identity condition";
        }
        if (!kind) continue;
        if (terminates(ifs.getThenStatement())) guards.push(this.guard(kind, ifs, fn));
      }
    }
    return guards;
  }

  /** Middleware on the route that compares request input with the identity and rejects on mismatch. */
  private middlewareGuards(chain: Fn[]): Guard[] {
    const guards: Guard[] = [];
    for (const mw of chain) {
      const req = mw.getParameters()[0]?.getName();
      if (!req) continue;
      const names = this.propagate(mw, { identity: new Set(), request: new Set() }, req);
      for (const ifs of mw.getDescendantsOfKind(SyntaxKind.IfStatement)) {
        const cond = ifs.getExpression();
        if (this.mentionsIdentity(cond, names, req) && this.mentionsRequest(cond, names, req) && terminates(ifs.getThenStatement())) {
          guards.push(this.guard("request value compared with identity", ifs, mw));
        }
      }
    }
    return guards;
  }

  /** A data access whose query also receives an identity-only value (e.g. `WHERE id = $1 AND owner = $2`). */
  private queryGuards(paths: CandidatePath[], all: Map<Fn, { names: Names; req?: string }>): Guard[] {
    const guards: Guard[] = [];
    for (const p of paths) {
      const sinkHop = p.hops.at(-1)!;
      const fn = this.fnAt(sinkHop.fn);
      const call = fn && this.callAt(fn, sinkHop);
      const info = fn && all.get(fn);
      if (!call || !info) continue;
      if (call.getArguments().some((a) => this.mentionsIdentity(a, info.names, info.req))) guards.push(this.guard("query constrained by identity", call, fn));
    }
    return guards;
  }

  /** Whether a check protects an access: it sits on the access path, and for a write it runs before the write. */
  private covers(g: Guard, a: Access, all: Map<Fn, { names: Names; req?: string }>): boolean {
    if (g.kind === "query constrained by identity") return g.file === a.path.hops.at(-1)!.file && g.line === a.path.hops.at(-1)!.line;
    const onPath = a.path.hops.some((h) => h.fn.file === g.fn.file && h.fn.startLine === g.fn.startLine);
    const isMiddleware = ![...all.keys()].some((fn) => this.tracer.functionRef(fn).file === g.fn.file && fn.getStartLineNumber() === g.fn.startLine);
    if (isMiddleware) return true;
    if (!onPath) return false;
    if (a.kind === "read") return true;
    // For a write, the check must come before the call that leads to the write within the same function.
    const step = a.path.hops.find((h) => (h.kind === "call" || h.kind === "sink") && h.fn.file === g.fn.file && h.fn.startLine === g.fn.startLine);
    return step !== undefined && g.line < step.line;
  }

  // ---- data accesses -------------------------------------------------------------------------------

  private statementAt(p: CandidatePath): { sql: string; verb: StatementVerb; tables: string[]; call: CallExpression } | undefined {
    const sinkHop = p.hops.at(-1)!;
    const fn = this.fnAt(sinkHop.fn);
    const call = fn && this.callAt(fn, sinkHop);
    const first = call?.getArguments()[0];
    if (!call || !first) return undefined;
    const sql = evaluateSql(first).replace(/\s+/g, " ").trim();
    return { sql, call, ...describeStatement(sql) };
  }

  /**
   * Request fields read by a path's source statement: `req.params.id` inline, `const { id, other: alias } = req.params`,
   * or `const id = req.params.id`. One traced path can carry several (the tracer keeps one path per hop sequence).
   */
  private sourceFields(code: string): { location: Access["location"]; field: string; holder: string }[] {
    const out: { location: Access["location"]; field: string; holder: string }[] = [];
    const destructured = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?[\w.]*?\.(params|query|body)\b(?!\.)/.exec(code);
    if (destructured) {
      for (const part of destructured[1].split(",")) {
        const [field, alias] = part.split(":").map((x) => x.trim().split("=")[0].trim());
        if (field) out.push({ location: destructured[2] as Access["location"], field, holder: alias || field });
      }
    }
    const single = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?[\w.]*?\.(params|query|body)\.(\w+)/.exec(code);
    if (single) out.push({ location: single[2] as Access["location"], field: single[3], holder: single[1] });
    if (!destructured && !single) {
      for (const m of code.matchAll(/\b[\w.]*?\.(params|query|body)\.(\w+)/g)) out.push({ location: m[1] as Access["location"], field: m[2], holder: m[0] });
    }
    return out;
  }

  /** Follows one value (a variable name or an inline expression) through a path's calls; its name at the data access. */
  private follow(p: CandidatePath, start: string): string | undefined {
    let holder = start;
    const mentions = (node: Node) =>
      holder.includes(".") ? node.getText().replace(/\s+/g, "").includes(holder) : [node, ...node.getDescendants()].some((n) => Node.isIdentifier(n) && n.getText() === holder);
    for (let i = 1; i < p.hops.length; i++) {
      const hop = p.hops[i];
      const next = p.hops[i + 1];
      if (hop.kind === "propagate") {
        // (A "build" hop embeds the value into SQL text, where its own name is what the statement shows.)
        const decl = /(?:const|let|var)\s+(\w+)\s*=/.exec(hop.code);
        const fn = this.fnAt(hop.fn);
        const node = fn?.getDescendantsOfKind(SyntaxKind.VariableDeclaration).find((d) => d.getStartLineNumber() === hop.line && d.getName() === decl?.[1]);
        if (decl && node?.getInitializer() && mentions(node.getInitializer()!)) holder = decl[1];
      } else if (hop.kind === "call" && next?.kind === "param") {
        const caller = this.fnAt(hop.fn);
        const call = caller && this.callAt(caller, hop);
        const callee = this.fnAt(next.fn);
        const index = call?.getArguments().findIndex(mentions) ?? -1;
        const param = index >= 0 ? callee?.getParameters()[index]?.getNameNode() : undefined;
        if (!param || !Node.isIdentifier(param)) return undefined; // this field does not travel along this path
        holder = param.getText();
      }
    }
    return holder;
  }

  /** Identifier-driven data accesses along one path, one per identifier field that actually reaches the access. */
  private accesses(p: CandidatePath): Access[] {
    const source = p.hops.find((h) => h.kind === "source");
    const stmt = this.statementAt(p);
    if (!source || !stmt) return [];
    const kind: AccessKind = stmt.verb === "insert" || stmt.verb === "update" || stmt.verb === "delete" ? "write" : "read";
    const out: Access[] = [];
    for (const { location, field, holder } of this.sourceFields(source.code)) {
      if (location !== "params" && !ID_LIKE.test(field)) continue;
      const atSink = this.follow(p, holder);
      if (!atSink) continue;
      let column: string | undefined;
      if (p.sqlText) column = columnForValue(stmt.sql, { name: atSink });
      else {
        const bound = stmt.call.getArguments()[1];
        const elements = bound && Node.isArrayLiteralExpression(bound) ? bound.getElements() : [];
        const index = elements.findIndex((el) => [el, ...el.getDescendants()].some((n) => Node.isIdentifier(n) && n.getText() === atSink));
        if (index < 0) continue; // reaches the call, but not as a bound value
        column = columnForValue(stmt.sql, { placeholder: index + 1 });
      }
      out.push({ path: p, field, location, kind, verb: stmt.verb, sql: stmt.sql, tables: stmt.tables, column });
    }
    return out;
  }

  private dedupeAccesses(all: Access[]): Access[] {
    const seen = new Set<string>();
    return all.filter((a) => {
      const sink = a.path.hops.at(-1)!;
      const key = `${a.location}.${a.field}@${sink.file}:${sink.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

/** Stage 1 of access-control analysis over a project directory. */
export function assembleAccessContext(dir: string, project?: Project): AccessContext {
  return new AccessAnalyzer(path.resolve(dir), project).run();
}
