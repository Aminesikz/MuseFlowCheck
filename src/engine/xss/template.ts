// Server-side templates for XSS: `res.render(view, data)` places `data` into a template file. Stage 1 reads the
// template engine and its auto-escaping setting from the project's code, finds the view's template file, and lists
// every output construct with whether it escapes HTML — so a tainted value is a candidate only where it lands raw:
// auto-escaping off, or a construct that bypasses it (`|safe`, `<%- %>`, `{{{ }}}`, `!{}`).
import { readFileSync } from "node:fs";
import path from "node:path";
import { Node, SyntaxKind, type SourceFile } from "ts-morph";
import { discoverTemplateFiles } from "../crossfile/files.js";

/** Template syntaxes by how they mark output: `{{ }}` with filters, `<%= %>`, mustache `{{ }}` / `{{{ }}}`, pug `#{}` / `!{}`. */
export type TemplateFamily = "jinja" | "ejs" | "mustache" | "pug";

const ENGINES: { re: RegExp; name: string; family: TemplateFamily }[] = [
  { re: /\bswig\b/i, name: "swig", family: "jinja" },
  { re: /\bnunjucks\b/i, name: "nunjucks", family: "jinja" },
  { re: /\btwig\b/i, name: "twig", family: "jinja" },
  { re: /\bliquid\b/i, name: "liquid", family: "jinja" },
  { re: /\bejs\b/i, name: "ejs", family: "ejs" },
  { re: /\b(?:express-)?(?:handlebars|hbs)\b/i, name: "handlebars", family: "mustache" },
  { re: /\bmustache\b/i, name: "mustache", family: "mustache" },
  { re: /\bpug\b/i, name: "pug", family: "pug" },
  { re: /\bjade\b/i, name: "jade", family: "pug" },
];

function engineNamed(text: string): { name: string; family: TemplateFamily } | undefined {
  return ENGINES.find((e) => e.re.test(text));
}

/** The project's view setup, as read from its code: which engine renders which extension, where views live, and escaping. */
export interface ViewSetup {
  /** Engine per file extension (`.html` → swig), from `app.engine(ext, …)` and `app.set("view engine", …)`. */
  engines: Map<string, { name: string; family: TemplateFamily }>;
  /** The default extension, from `app.set("view engine", ext)`. */
  defaultExt?: string;
  /** Absolute view directories, from `app.set("views", …)`. */
  dirs: string[];
  /** Auto-escaping explicitly configured in code (`swig.setDefaults({ autoescape: false })`, `noEscape: true`), with where. */
  autoescape?: { on: boolean; at: string };
  /** An engine named only by the project's dependencies, used when the code does not register one. */
  fallback?: { name: string; family: TemplateFamily };
}

const literal = (n: Node | undefined) => (n && (Node.isStringLiteral(n) || Node.isNoSubstitutionTemplateLiteral(n)) ? n.getLiteralValue() : undefined);

/** A directory expression: a literal, `${__dirname}/x`, `__dirname + '/x'`, or `path.join|resolve(__dirname, 'x', …)`. */
function dirOf(n: Node, sf: SourceFile, root: string): string | undefined {
  const here = path.dirname(sf.getFilePath());
  const lit = literal(n);
  if (lit !== undefined) return path.resolve(root, lit);
  const text = n.getText().replace(/\s+/g, "");
  if (Node.isTemplateExpression(n)) {
    const m = /^`\$\{__dirname\}(.*)`$/.exec(text);
    if (m) return path.join(here, m[1]);
  }
  const plus = /^__dirname\+["'`](.*)["'`]$/.exec(text);
  if (plus) return path.join(here, plus[1]);
  if (Node.isCallExpression(n) && /^path\.(?:join|resolve)$/.test(n.getExpression().getText())) {
    const parts = n.getArguments().map((a) => (a.getText() === "__dirname" ? here : literal(a)));
    if (parts.every((p) => p !== undefined)) return path.resolve(...(parts as string[]));
  }
  return undefined;
}

const extOf = (e: string) => (e.startsWith(".") ? e : `.${e}`);

/** Reads the view setup from the project's source files (and its package.json for a fallback engine). */
export function readViewSetup(files: SourceFile[], root: string, rel: (sf: SourceFile) => string): ViewSetup {
  const setup: ViewSetup = { engines: new Map(), dirs: [] };
  for (const sf of files) {
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression();
      const method = Node.isPropertyAccessExpression(callee) ? callee.getName() : undefined;
      const [a, b] = call.getArguments();
      if (method === "set" && literal(a) === "view engine" && literal(b)) {
        const name = literal(b)!;
        setup.defaultExt = extOf(name);
        const engine = engineNamed(name);
        if (engine && !setup.engines.has(extOf(name))) setup.engines.set(extOf(name), engine);
      } else if (method === "set" && literal(a) === "views" && b) {
        const exprs = Node.isArrayLiteralExpression(b) ? b.getElements() : [b];
        for (const e of exprs) {
          const dir = dirOf(e, sf, root);
          if (dir) setup.dirs.push(dir);
        }
      } else if (method === "engine" && literal(a) && b) {
        const engine = engineNamed(b.getText()) ?? engineNamed(literal(a)!);
        if (engine) setup.engines.set(extOf(literal(a)!), engine);
      }
      // Escaping configured in code: `autoescape: <bool>` (swig, nunjucks, twig) or handlebars' `noEscape: <bool>`.
      for (const arg of call.getArguments()) {
        if (!Node.isObjectLiteralExpression(arg)) continue;
        for (const p of arg.getProperties()) {
          if (!Node.isPropertyAssignment(p)) continue;
          const value = p.getInitializer()?.getKind();
          const bool = value === SyntaxKind.TrueKeyword ? true : value === SyntaxKind.FalseKeyword ? false : undefined;
          if (bool === undefined) continue;
          const at = `${rel(sf)}:${p.getStartLineNumber()}`;
          if (p.getName() === "autoescape") setup.autoescape = { on: bool, at };
          else if (p.getName() === "noEscape") setup.autoescape = { on: !bool, at };
        }
      }
    }
  }
  try {
    const pkg = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    setup.fallback = deps.map(engineNamed).find((e) => e !== undefined);
  } catch {
    // no package.json at the root: no fallback engine
  }
  return setup;
}

/** One place a template writes a value into the page. */
export interface TemplateOutput {
  line: number;
  code: string;
  /** The data names the expression reads (aliases already resolved to the data key they iterate). */
  names: string[];
  /** True when the value is written without HTML escaping. */
  raw: boolean;
  /** How it escapes or why it does not, e.g. "swig auto-escaping is off (server.js:137)". */
  how: string;
}

/** A view's template file and the engine that renders it. */
export interface Template {
  file: string;
  engine: string;
  family: TemplateFamily;
  lines: string[];
  outputs: TemplateOutput[];
}

const NOT_NAMES = new Set(["true", "false", "null", "undefined", "and", "or", "not", "in", "is", "if", "else", "this", "typeof", "new", "loop"]);

/** Names an expression reads: identifiers not after a dot, outside string literals. */
function namesIn(expr: string): string[] {
  const bare = expr.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, "");
  return [...new Set([...bare.matchAll(/(?<![.\w$])[A-Za-z_$][\w$]*/g)].map((m) => m[0]).filter((n) => !NOT_NAMES.has(n)))];
}

const lineAt = (text: string, index: number) => text.slice(0, index).split("\n").length;

/** Escaping state of the jinja family, honoring `{% autoescape false %}` … `{% endautoescape %}` blocks. */
function jinjaOutputs(text: string, engine: string, autoescape: { on: boolean; at?: string }): TemplateOutput[] {
  const out: TemplateOutput[] = [];
  const alias = new Map<string, string[]>();
  const blocks: boolean[] = []; // autoescape on/off per open block
  const token = /\{%-?\s*([\s\S]*?)\s*-?%\}|\{\{-?\s*([\s\S]*?)\s*-?\}\}/g;
  const resolve = (names: string[]) => names.flatMap((n) => alias.get(n) ?? [n]);
  let raw = false; // inside {% raw %} / {% verbatim %}: literal text
  for (const m of text.matchAll(token)) {
    const [, tag, expr] = m;
    if (tag !== undefined) {
      const words = tag.split(/\s+/);
      if (/^(?:raw|verbatim)$/.test(words[0])) raw = true;
      else if (/^end(?:raw|verbatim)$/.test(words[0])) raw = false;
      else if (raw) continue;
      else if (words[0] === "autoescape") blocks.push(!/^(?:false|off|no)$/i.test(words[1] ?? "true"));
      else if (words[0] === "endautoescape") blocks.pop();
      else if (words[0] === "for") {
        const f = /^for\s+([\w$]+)(?:\s*,\s*([\w$]+))?\s+in\s+([\s\S]+)$/.exec(tag);
        if (f) for (const v of [f[1], f[2]].filter(Boolean)) alias.set(v!, resolve(namesIn(f[3])));
      } else if (words[0] === "set") {
        const s = /^set\s+([\w$]+)\s*=\s*([\s\S]+)$/.exec(tag);
        if (s) alias.set(s[1], resolve(namesIn(s[2])));
      }
      continue;
    }
    if (raw || expr === undefined) continue;
    const [value, ...filters] = expr.split("|").map((f) => f.trim());
    const filterNames = filters.map((f) => f.split(/[\s(:]/)[0]);
    const on = blocks.length > 0 ? blocks.at(-1)! : autoescape.on;
    let isRaw: boolean;
    let how: string;
    if (filterNames.some((f) => f === "safe" || f === "raw")) [isRaw, how] = [true, `the '${filterNames.find((f) => f === "safe" || f === "raw")}' filter disables ${engine} escaping`];
    else if (filterNames.some((f) => f === "escape" || f === "e")) [isRaw, how] = [false, `the '${filterNames.find((f) => f === "escape" || f === "e")}' filter HTML-escapes it`];
    else if (blocks.length > 0) [isRaw, how] = [!on, `inside {% autoescape ${on ? "true" : "false"} %}`];
    else [isRaw, how] = [!on, `${engine} auto-escaping is ${on ? "on" : "off"}${autoescape.at ? ` (${autoescape.at})` : " (the engine's default)"}`];
    out.push({ line: lineAt(text, m.index!), code: m[0], names: resolve(namesIn(value)), raw: isRaw, how });
  }
  return out;
}

function ejsOutputs(text: string): TemplateOutput[] {
  return [...text.matchAll(/<%([=-])\s*([\s\S]*?)\s*-?%>/g)].map((m) => ({
    line: lineAt(text, m.index!),
    code: m[0],
    names: namesIn(m[2]),
    raw: m[1] === "-",
    how: m[1] === "-" ? "EJS <%- %> writes it unescaped" : "EJS <%= %> HTML-escapes it",
  }));
}

/** Mustache / handlebars: `{{{x}}}` and `{{& x}}` are raw; inside `{{#each list}}` bare names are fields of `list`. */
function mustacheOutputs(text: string, engine: string, autoescape: { on: boolean; at?: string }): TemplateOutput[] {
  const out: TemplateOutput[] = [];
  const blocks: string[][] = [];
  for (const m of text.matchAll(/\{\{\{\s*([\s\S]*?)\s*\}\}\}|\{\{([#/^!>&]?)\s*([\s\S]*?)\s*\}\}/g)) {
    const triple = m[1];
    const sigil = m[2] ?? "";
    const expr = triple ?? m[3];
    if (sigil === "#" || sigil === "^") {
      // `{{#each list}}` / `{{#with obj}}` / a mustache section `{{#list}}` change the context; `{{#if x}}` does not.
      const [helper, ...rest] = expr.split(/\s+/);
      const context = rest.length === 0 ? namesIn(helper) : helper === "each" || helper === "with" ? namesIn(rest.join(" ")) : [];
      blocks.push([...context, ...(blocks.at(-1) ?? [])]);
      continue;
    }
    if (sigil === "/") {
      blocks.pop();
      continue;
    }
    if (sigil === "!" || sigil === ">") continue;
    const names = [...namesIn(expr), ...(blocks.at(-1) ?? [])]; // a bare name inside a block may be a field of its context
    const raw = triple !== undefined || sigil === "&" || !autoescape.on;
    const how = triple !== undefined ? `${engine} {{{ }}} writes it unescaped` : sigil === "&" ? `${engine} {{& }} writes it unescaped` : autoescape.on ? `${engine} {{ }} HTML-escapes it` : `${engine} escaping is off (${autoescape.at})`;
    out.push({ line: lineAt(text, m.index!), code: m[0], names, raw, how });
  }
  return out;
}

/** Pug / jade: `#{x}` and `tag= x` escape; `!{x}` and `tag!= x` do not; `each item in list` aliases `item`. */
function pugOutputs(text: string, engine: string): TemplateOutput[] {
  const out: TemplateOutput[] = [];
  const alias = new Map<string, string[]>();
  const resolve = (names: string[]) => names.flatMap((n) => alias.get(n) ?? [n]);
  text.split("\n").forEach((line, i) => {
    const each = /^\s*(?:each|for)\s+([\w$]+)(?:\s*,\s*([\w$]+))?\s+in\s+(.+)$/.exec(line);
    if (each) for (const v of [each[1], each[2]].filter(Boolean)) alias.set(v!, resolve(namesIn(each[3])));
    for (const m of line.matchAll(/([#!])\{([^}]*)\}/g)) {
      out.push({ line: i + 1, code: m[0], names: resolve(namesIn(m[2])), raw: m[1] === "!", how: m[1] === "!" ? `${engine} !{} writes it unescaped` : `${engine} #{} HTML-escapes it` });
    }
    const buffered = /^\s*[\w.#:-]*(?:\([^)]*\))?(!?=)\s*(.+)$/.exec(line);
    if (buffered && !each) {
      const raw = buffered[1] === "!=";
      out.push({ line: i + 1, code: line.trim(), names: resolve(namesIn(buffered[2])), raw, how: raw ? `${engine} != writes it unescaped` : `${engine} = HTML-escapes it` });
    }
  });
  return out;
}

/** Finds and parses a view's template, or says why it cannot (not found, or no engine recognized for it). */
export class Templates {
  private files?: string[];
  private readonly cache = new Map<string, Template | string>();

  constructor(
    private readonly root: string,
    private readonly setup: () => ViewSetup,
  ) {}

  /** The parsed template for `view`, or the reason it could not be read. */
  get(view: string): Template | string {
    let hit = this.cache.get(view);
    if (hit === undefined) {
      hit = this.load(view);
      this.cache.set(view, hit);
    }
    return hit;
  }

  private load(view: string): Template | string {
    const setup = this.setup();
    const file = this.find(view, setup);
    if (!file) return `template for view '${view}' not found`;
    const ext = path.extname(file);
    const engine = setup.engines.get(ext) ?? engineNamed(ext.slice(1)) ?? (ext === setup.defaultExt ? setup.fallback : undefined) ?? setup.fallback;
    if (!engine) return `no template engine recognized for ${path.relative(this.root, file)}`;
    const text = readFileSync(file, "utf8");
    const autoescape = setup.autoescape ?? { on: true }; // every supported engine escapes by default
    const outputs =
      engine.family === "jinja"
        ? jinjaOutputs(text, engine.name, autoescape)
        : engine.family === "ejs"
          ? ejsOutputs(text)
          : engine.family === "mustache"
            ? mustacheOutputs(text, engine.name, autoescape)
            : pugOutputs(text, engine.name);
    return { file: path.relative(this.root, file), engine: engine.name, family: engine.family, lines: text.split(/\r?\n/), outputs };
  }

  /** `<views dir>/<view><ext>`; else a template file whose path ends in `/<view>.<ext>`, preferring one under `views/`. */
  private find(view: string, setup: ViewSetup): string | undefined {
    this.files ??= discoverTemplateFiles(this.root);
    const exts = path.extname(view) ? [""] : [...new Set([setup.defaultExt, ...setup.engines.keys()].filter((e): e is string => e !== undefined))];
    for (const dir of setup.dirs) {
      for (const ext of exts) {
        const candidate = path.resolve(dir, view + ext);
        if (this.files.includes(candidate)) return candidate;
      }
    }
    const tail = `/${view.replace(/^\/+/, "")}`;
    const matches = this.files.filter((f) => {
      const noExt = path.extname(view) ? f : f.slice(0, -path.extname(f).length);
      return noExt.split(path.sep).join("/").endsWith(tail) && (exts[0] === "" || exts.length === 0 || exts.includes(path.extname(f)));
    });
    return matches.find((f) => f.split(path.sep).includes("views")) ?? matches[0];
  }
}
