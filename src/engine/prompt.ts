// Prompt construction for single-file SQL injection analysis.
// Keep this codebase-agnostic: describe sources, sinks and sanitizers by behavior, never by the names in any test app.

const FINDING_SCHEMA = `interface Finding {
  type: "SQL Injection";
  cwe: "CWE-89";
  severity: "critical" | "high" | "medium" | "low";
  file: string;            // the file path given below
  sourceLine: number;      // line where untrusted input first enters the code
  sinkLine: number;        // line of the call that EXECUTES the query (not the line where the SQL string is built)
  taintPath: string[];     // ordered hops, each "L<line>: <short code excerpt>":
                           //   [source, ...intermediate steps (assignments, helper calls), string-building step, execute call]
                           //   at least 3 hops; if the string is built inside the execute call itself, the build and execute hops share that line
  explanation: string;     // plain language: why this is exploitable and what an attacker could do
  suggestedPatch: string;  // corrected code using the SAME database library's parameter binding, matching the file's style
  confidence: "suspected";
}`;

/** Prefixes each line with its 1-based number so the model can cite exact lines. */
export function numberLines(source: string): string {
  const lines = source.split(/\r?\n/);
  const width = String(lines.length).length;
  return lines.map((line, i) => `${String(i + 1).padStart(width, " ")} | ${line}`).join("\n");
}

export function buildSqliPrompt(filePath: string, source: string): string {
  return `You are a senior security code reviewer. Analyze the single JavaScript/TypeScript file below for SQL injection (CWE-89) ONLY. Ignore every other vulnerability class.

Reason about data flow, not about names. Every list of methods, libraries or frameworks below is illustrative, NOT exhaustive: anything that behaves like a source, sink or sanitizer as defined counts, even if it is not named here or the code style is unfamiliar.

1. SOURCE — untrusted, attacker-controllable input
Any value that originates from an incoming request. Examples: Express-style req.query, req.params, req.body, req.headers, req.cookies; the equivalents in other frameworks (Koa ctx.query / ctx.params / ctx.request.body, Fastify request.query / request.body, Next.js API route request objects, etc.).
Taint PROPAGATES through:
- destructuring, reassignment, and intermediate variables;
- object/array properties and collections built from tainted values;
- string operations that do not neutralize SQL meaning (trim, toLowerCase, split, slice, replace of unrelated characters, map, join, String());
- functions defined in this file: a tainted argument makes the parameter tainted inside the function, and a return value built from it is tainted at the call site.

2. SINK — a call that executes a SQL string
Any function or method that hands a SQL text string to a database driver, query builder or ORM for execution. Recognize it by behavior: it receives a string containing SQL (SELECT, INSERT, UPDATE, DELETE, WHERE, ORDER BY, ...) and runs it. Examples:
- node-postgres pool.query / client.query; mysql / mysql2 connection.query / connection.execute / pool.query;
- better-sqlite3 db.prepare(sql).run / .get / .all, db.exec; sqlite3 db.run / db.all / db.get;
- knex.raw / knex.schema.raw / whereRaw / orderByRaw / havingRaw; sequelize.query, sequelize.literal;
- Prisma $queryRawUnsafe / $executeRawUnsafe; TypeORM query / createQueryBuilder().where(<string>);
- any generic wrapper such as db.query, db.execute, runQuery(sql), repo.raw(sql).
The sinkLine is the line of that EXECUTE call.

3. VULNERABLE FLOW — what to report
Tainted data becomes part of the SQL TEXT itself, by any form of string construction: \`+\`, \`+=\`, .concat(), template-literal interpolation \`\${...}\`, Array.prototype.join, util.format / printf-style helpers, or a helper function that returns such a string — and that string then reaches a sink.
This includes tainted values used as identifiers or keywords (column names, table names, ORDER BY direction, LIMIT) when they are not allowlisted.

4. SAFE — do NOT report
- Parameterized / bound queries: the SQL text contains only placeholders ($1, ?, :name, @name) and the values are passed separately as bindings. This is safe no matter which library is used.
- Tagged-template SQL helpers that bind interpolations as parameters (e.g. postgres.js sql\`...\`, Prisma $queryRaw\`...\`, slonik sql\`...\`) — but the "Unsafe" variants or plain (untagged) template strings ARE sinks.
- Query-builder / ORM methods that bind values internally (object or value arguments to where/insert/update/find, etc.).
- Values neutralized before reaching SQL text: converted to a number (Number(), parseInt(), parseFloat(), unary +) or validated against a fixed allowlist (includes on a constant list, switch/map lookup to constant strings, enum check), or escaped with the driver's escape function (escape(), escapeId(), format with %L/%I, etc.).
- Input that flows only into a function defined in ANOTHER file — you cannot see that body, so do not guess.
Report only flows where both the source and the executing sink are visible in this file. If you are not sure tainted data reaches SQL text without neutralization, do not report it.

SEVERITY: "critical" if an unauthenticated or low-privilege user can read or modify data beyond their own; "high" for injection reachable only behind authentication or with limited impact; lower only with a clear reason.

OUTPUT
Return ONLY a JSON array of objects matching this TypeScript schema — no prose, no markdown fences. Return [] if there are no findings.
Report one finding per executing sink. If several sources reach the same sink, use the earliest as sourceLine and mention the others in the explanation.

${FINDING_SCHEMA}

FILE: ${filePath}
(line numbers are prefixed as "N | " and are not part of the code)

${numberLines(source)}`;
}
