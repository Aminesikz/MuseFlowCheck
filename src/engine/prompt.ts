// Prompt construction for single-file SQL injection analysis.

const FINDING_SCHEMA = `interface Finding {
  type: "SQL Injection";
  cwe: "CWE-89";
  severity: "critical" | "high" | "medium" | "low";
  file: string;            // the file path given below
  sourceLine: number;      // line where untrusted input enters (use the line numbers shown)
  sinkLine: number;        // line where the tainted SQL string is executed or built
  taintPath: string[];     // hops from source to sink; for now exactly two: [source, sink], each a short code excerpt with its line, e.g. "L12: const id = req.params.id"
  explanation: string;     // plain language: why this is exploitable and what an attacker could do
  suggestedPatch: string;  // corrected code for the sink using a parameterized query, same DB library and style as the file
  confidence: "suspected";
}`;

/** Prefixes each line with its 1-based number so the model can cite exact lines. */
export function numberLines(source: string): string {
  const lines = source.split(/\r?\n/);
  const width = String(lines.length).length;
  return lines.map((line, i) => `${String(i + 1).padStart(width, " ")} | ${line}`).join("\n");
}

export function buildSqliPrompt(filePath: string, source: string): string {
  return `You are a security code reviewer. Analyze the single JavaScript/TypeScript file below for SQL injection (CWE-89) ONLY. Ignore every other vulnerability class.

DEFINITIONS
- Source: untrusted HTTP input — req.query, req.params, req.body — including any variable assigned, destructured, or derived from them (e.g. \`const { id } = req.params\`, \`const name = req.body.name.trim()\`).
- Sink: a SQL statement built from a source by string concatenation (\`+\`, \`+=\`, \`.concat()\`) or template-literal interpolation (\`\${...}\`), that is then executed (e.g. db.query, pool.query, client.query, connection.execute, knex.raw, sequelize.query) or passed on as raw SQL text.

REPORT ONLY genuine string-concatenation-into-SQL where both the source and the sink are visible in this file.
DO NOT REPORT:
- Parameterized queries, where the SQL text uses placeholders ($1, ?, :name) and the values are passed separately — this is the safe pattern.
- Query-builder/ORM calls that bind values (e.g. knex.where({ id }), Model.findOne({ where: { id } })).
- Values strictly validated against an allowlist, or converted with Number()/parseInt() before use.
- Input that only flows into a function defined in another file — you cannot see that function's body.
If you are not sure the input reaches SQL text unescaped, do not report it.

SEVERITY: "critical" if an unauthenticated or low-privilege user can read or modify data beyond their own; "high" for injection reachable only behind authentication or with limited impact; lower only with a clear reason.

OUTPUT
Return ONLY a JSON array of objects matching this TypeScript schema — no prose, no markdown fences. Return [] if there are no findings. Report each distinct sink once.

${FINDING_SCHEMA}

FILE: ${filePath}
(line numbers are prefixed as "N | " and are not part of the code)

${numberLines(source)}`;
}
