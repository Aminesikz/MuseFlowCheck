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
  suggestedPatch: string;  // corrected code using the SAME database library's parameter binding (see BINDING below), matching the file's style
  confidence: "suspected";
}`;

/** Patterns that neutralize SQL injection, stated as general principles (shared with the cross-file judge). */
export const SAFE_PATTERNS = `- Parameterized / bound queries: the SQL text contains only placeholders ($1, ?, :name, @name) and the values are passed separately as bindings. This is safe no matter which library is used.
- Tagged-template SQL helpers that bind interpolations as parameters (e.g. postgres.js sql\`...\`, Prisma $queryRaw\`...\`, slonik sql\`...\`) — but the "Unsafe" variants or plain (untagged) template strings ARE sinks.
- Query-builder / ORM methods that bind values internally (object or value arguments to where/insert/update/find, etc.).
- Values neutralized before reaching SQL text: converted to a number (Number(), parseInt(), parseFloat(), unary +) or validated against a fixed allowlist (includes on a constant list, switch/map lookup to constant strings, enum check), or escaped with the driver's escape function (escape(), escapeId(), format with %L/%I, etc.).`;

/**
 * How each common SQL library binds values, by package — illustrative: a library not listed binds the way its own
 * documentation says. Used to make a suggested patch use the dialect of the code it fixes.
 */
const BINDING_STYLES: [RegExp, string][] = [
  [/^(?:pg|pg-pool|pg-promise|postgres|slonik|@neondatabase\/serverless|@vercel\/postgres)$/, "PostgreSQL — numbered placeholders $1, $2, … with the values in an array: pool.query('… WHERE id = $1', [id])"],
  [/^(?:mysql|mysql2|mariadb)$/, "MySQL — ? placeholders with the values in an array: connection.query('… WHERE id = ?', [id]) or connection.execute(…); ?? for an identifier"],
  [/^(?:better-sqlite3|sqlite3|sqlite|@libsql\/client)$/, "SQLite — ? placeholders (or :name / @name / $name), the values passed when it runs: db.prepare('… WHERE id = ?').get(id); sqlite3: db.get('… WHERE id = ?', [id], cb)"],
  [/^(?:mssql|tedious)$/, "SQL Server — @name parameters declared on the request: request.input('id', sql.Int, id).query('… WHERE id = @id')"],
  [/^oracledb$/, "Oracle — :name bind variables with a bind object: connection.execute('… WHERE id = :id', { id })"],
  [/^knex$/, "knex — ? placeholders with a bindings array (?? for an identifier): knex.raw('… WHERE id = ?', [id]); or the query builder, which binds: .where({ id })"],
  [/^sequelize$/, "Sequelize — replacements: sequelize.query('… WHERE id = :id', { replacements: { id } }) (or ? with an array of replacements)"],
  [/^typeorm$/, "TypeORM — the driver's placeholders with a parameters array: manager.query('… WHERE id = $1', [id]) on PostgreSQL, '… = ?' on MySQL/SQLite; or the query builder with named parameters: .where('id = :id', { id })"],
  [/^@prisma\/client$/, "Prisma — the tagged template, which binds interpolations: prisma.$queryRaw`… WHERE id = ${id}` (never $queryRawUnsafe with a built string)"],
];

/** The binding style of a SQL package, when it is one of the common ones. */
export function bindingStyle(pkg: string | undefined): string | undefined {
  return pkg ? BINDING_STYLES.find(([re]) => re.test(pkg))?.[1] : undefined;
}

/** For the patch: bind values in the dialect of the library the code uses, never a different one's placeholders. */
export const BINDING_GUIDE = `BINDING — the patch must bind values the way the library the code uses does, never with another library's placeholders. For example (illustrative): PostgreSQL drivers $1, $2 with a values array; MySQL / MariaDB ? with a values array; SQLite ? (or :name) with the values passed when it runs; SQL Server @name declared with request.input(name, value); knex / Sequelize their bindings or replacements, or the query builder. Keep identifiers that cannot be bound (column names, sort direction) on a fixed allowlist.`;

/**
 * Severity as an ordered decision: impact outranks reachability, so a finding that needs a login but
 * crosses data boundaries is still critical. The first matching rule wins — no overlap between levels.
 */
export const SEVERITY_GUIDE = `SEVERITY — check these rules IN ORDER and assign the FIRST one that matches:
1. "critical" — the attacker can read or modify data beyond their own scope (other users' records, other tenants or organizations, other tables, or the whole database), OR the flaw can be exploited without authentication. Requiring a login does NOT lower severity when this rule matches.
2. "high" — exploitable, but the impact is confined to the attacker's own data/scope, or is meaningfully constrained by something visible in the code.
3. "medium" or "low" — only for a specific, clearly stated reason (e.g. a strong precondition, or no sensitive data reachable).
For SQL injection: unless the code shows otherwise, an injectable query can rewrite its own filter (e.g. drop a WHERE condition, add UNION SELECT), so it normally reaches data beyond the attacker's scope.`;

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
${SAFE_PATTERNS}
- Input that flows only into a function defined in ANOTHER file — you cannot see that body, so do not guess.
Report only flows where both the source and the executing sink are visible in this file. If you are not sure tainted data reaches SQL text without neutralization, do not report it.

${SEVERITY_GUIDE}

${BINDING_GUIDE}

OUTPUT
Return ONLY a JSON array of objects matching this TypeScript schema — no prose, no markdown fences. Return [] if there are no findings.
Report one finding per executing sink. If several sources reach the same sink, use the earliest as sourceLine and mention the others in the explanation.

${FINDING_SCHEMA}

FILE: ${filePath}
(line numbers are prefixed as "N | " and are not part of the code)

${numberLines(source)}`;
}
