// Static SQL helpers for access-control context: schema ownership columns and what a query reads or writes.
// Approximate by design — the output is evidence for the judge, not a verdict.
import { readFileSync } from "node:fs";
import { Node, SyntaxKind } from "ts-morph";

export interface SchemaColumn {
  name: string;
  line: number;
  /** `REFERENCES table(column)`, when declared. */
  references?: { table: string; column: string };
}

export interface SchemaTable {
  name: string;
  file: string; // as given by the caller (relative to the scan root)
  line: number;
  columns: SchemaColumn[];
}

/** `CREATE TABLE` statements: table names, columns, and foreign keys (inline or as table constraints). */
export function parseSchema(text: string, file: string): SchemaTable[] {
  const tables: SchemaTable[] = [];
  const lineOf = (index: number) => text.slice(0, index).split("\n").length;
  const create = /create\s+table\s+(?:if\s+not\s+exists\s+)?["`]?(?:\w+["`]?\.["`]?)?(\w+)["`]?\s*\(/gi;
  for (let m = create.exec(text); m; m = create.exec(text)) {
    // Body: up to the parenthesis that closes the column list.
    let depth = 1;
    let i = create.lastIndex;
    for (; i < text.length && depth > 0; i++) depth += text[i] === "(" ? 1 : text[i] === ")" ? -1 : 0;
    const bodyStart = create.lastIndex;
    const body = text.slice(bodyStart, i - 1);
    const table: SchemaTable = { name: m[1].toLowerCase(), file, line: lineOf(m.index), columns: [] };

    let offset = 0;
    for (const part of splitTopLevel(body)) {
      const at = body.indexOf(part, offset);
      offset = at + part.length;
      const def = part.trim();
      const fk = /^(?:constraint\s+\w+\s+)?foreign\s+key\s*\(\s*["`]?(\w+)["`]?\s*\)\s*references\s+["`]?(\w+)["`]?\s*(?:\(\s*["`]?(\w+)["`]?\s*\))?/i.exec(def);
      if (fk) {
        const col = table.columns.find((c) => c.name === fk[1].toLowerCase());
        if (col) col.references = { table: fk[2].toLowerCase(), column: (fk[3] ?? "id").toLowerCase() };
        continue;
      }
      if (/^(?:constraint|primary\s+key|unique|check|index|key)\b/i.test(def)) continue;
      const col = /^["`]?(\w+)["`]?\s+\w+/.exec(def);
      if (!col) continue;
      const ref = /references\s+["`]?(\w+)["`]?\s*(?:\(\s*["`]?(\w+)["`]?\s*\))?/i.exec(def);
      table.columns.push({
        name: col[1].toLowerCase(),
        line: lineOf(bodyStart + at + part.indexOf(def)),
        ...(ref ? { references: { table: ref[1].toLowerCase(), column: (ref[2] ?? "id").toLowerCase() } } : {}),
      });
    }
    tables.push(table);
  }
  return tables;
}

function splitTopLevel(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "(") depth++;
    else if (body[i] === ")") depth--;
    else if (body[i] === "," && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(body.slice(start));
  return parts.filter((p) => p.trim() !== "");
}

export function readSchema(files: { abs: string; rel: string }[]): SchemaTable[] {
  return files.flatMap((f) => parseSchema(readFileSync(f.abs, "utf8"), f.rel));
}

/** Marker for an interpolated value inside evaluated SQL text: `{{name}}`. */
const hole = (name: string) => `{{${name}}}`;

/**
 * The SQL text an expression evaluates to, as far as it is static: string literals and `+` / template
 * concatenation, constants, and `let sql = …; sql += …` built up earlier in the same function.
 * Interpolated values become `{{name}}`.
 */
export function evaluateSql(expr: Node, depth = 0): string {
  const e = Node.isParenthesizedExpression(expr) ? expr.getExpression() : expr;
  if (depth > 6) return hole(e.getText());
  if (Node.isStringLiteral(e) || Node.isNoSubstitutionTemplateLiteral(e)) return e.getLiteralValue();
  if (Node.isTemplateExpression(e)) {
    return (
      e.getHead().getLiteralText() +
      e
        .getTemplateSpans()
        .map((span) => evaluateSql(span.getExpression(), depth + 1) + span.getLiteral().getLiteralText())
        .join("")
    );
  }
  if (Node.isBinaryExpression(e) && e.getOperatorToken().getKind() === SyntaxKind.PlusToken) {
    return evaluateSql(e.getLeft(), depth + 1) + evaluateSql(e.getRight(), depth + 1);
  }
  if (Node.isIdentifier(e)) return evaluateIdentifier(e, depth);
  return hole(e.getText());
}

function evaluateIdentifier(id: Node, depth: number): string {
  const name = id.getText();
  // Nearest enclosing scope that declares it: the function body, then the file.
  for (let scope: Node | undefined = id.getParent(); scope; scope = scope.getParent()) {
    if (!Node.isBlock(scope) && !Node.isSourceFile(scope)) continue;
    const decl = scope
      .getStatements()
      .flatMap((st) => (Node.isVariableStatement(st) ? st.getDeclarations() : []))
      .find((d) => d.getName() === name);
    if (!decl) continue;
    const init = decl.getInitializer();
    if (!init || !isStringish(init)) return hole(name);
    let text = evaluateSql(init, depth + 1);
    // `sql += …` between the declaration and this use (conditional branches included: an over-approximation).
    for (const bin of scope.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      if (bin.getStart() <= decl.getStart() || bin.getStart() >= id.getStart()) continue;
      if (bin.getOperatorToken().getKind() === SyntaxKind.PlusEqualsToken && bin.getLeft().getText() === name) {
        text += evaluateSql(bin.getRight(), depth + 1);
      }
    }
    return text;
  }
  return hole(name);
}

function isStringish(node: Node): boolean {
  return (
    Node.isStringLiteral(node) ||
    Node.isNoSubstitutionTemplateLiteral(node) ||
    Node.isTemplateExpression(node) ||
    (Node.isBinaryExpression(node) && node.getOperatorToken().getKind() === SyntaxKind.PlusToken)
  );
}

export type StatementVerb = "select" | "insert" | "update" | "delete" | "unknown";

/** Statement kind and the tables it names (FROM / JOIN / INTO / UPDATE). */
export function describeStatement(sql: string): { verb: StatementVerb; tables: string[] } {
  const verb = (/^\s*(select|insert|update|delete|with)\b/i.exec(sql)?.[1].toLowerCase() ?? "unknown") as StatementVerb | "with";
  const tables = new Set<string>();
  for (const m of sql.matchAll(/\b(?:from|join|into|update)\s+["`]?(\w+)["`]?/gi)) tables.add(m[1].toLowerCase());
  const resolved: StatementVerb = verb === "with" ? (/\b(update|delete|insert)\b/i.exec(sql)?.[1].toLowerCase() as StatementVerb) ?? "select" : verb;
  return { verb: resolved, tables: [...tables] };
}

/**
 * The column a value is compared with or written to: `col = $n`, `col = ?` (n-th), `col = {{name}}`,
 * or the n-th column of an `INSERT (...) VALUES`.
 */
export function columnForValue(sql: string, value: { placeholder?: number; name?: string }): string | undefined {
  const col = String.raw`["\`]?(?:\w+["\`]?\.["\`]?)?(\w+)["\`]?`;
  const op = String.raw`\s*(?:=|<>|!=|<=|>=|<|>|\bin\b\s*\(?|\blike\b|\bilike\b)\s*'?%?`;
  if (value.placeholder !== undefined) {
    const n = value.placeholder;
    const dollar = new RegExp(`${col}${op}\\$${n}(?!\\d)`, "i").exec(sql);
    if (dollar) return dollar[1].toLowerCase();
    const named = /\?/g;
    let count = 0;
    for (let m = named.exec(sql); m; m = named.exec(sql)) {
      if (++count !== n) continue;
      const before = new RegExp(`${col}${op}$`, "i").exec(sql.slice(0, m.index));
      if (before) return before[1].toLowerCase();
    }
    const insert = /insert\s+into\s+\w+\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/i.exec(sql);
    if (insert) {
      const cols = insert[1].split(",").map((c) => c.trim().replace(/["`]/g, "").toLowerCase());
      const vals = insert[2].split(",").map((v) => v.trim());
      const idx = vals.findIndex((v) => v === `$${n}`);
      if (idx >= 0) return cols[idx];
    }
  }
  if (value.name) {
    const m = new RegExp(`${col}${op}\\{\\{${value.name}\\}\\}`, "i").exec(sql);
    if (m) return m[1].toLowerCase();
  }
  return undefined;
}
