# Generalization test cases

Short standalone routes for checking that detection works on code the prompt wasn't shaped around. Each uses a different library, framework or string-building style than `fixtures/`. They're for validation only: they aren't part of the published package, and their dependencies aren't installed (the files are scanned, not run). The files carry no hint comments; the expected results are listed here.

| File | Pattern | Expected |
| --- | --- | --- |
| `concat-helper.js` | mysql2, `req.body` destructured → reassigned → local helper building SQL with `.concat()` | **1 finding.** Source L13, sink L16 (`conn.query`). Path goes through the helper (L9) and the build (L15). |
| `sequelize-template.ts` | TypeScript, `sequelize.query` with template-literal interpolation of a lowercased `req.params` value | **1 finding.** Source L8, sink L9 (`sequelize.query(`; the SQL argument is on L10). |
| `knex-raw-join.js` | Koa `ctx.query`, `.split()`/`.join()` column list and an ORDER BY direction concatenated into `knex.raw` | **1 finding** (one sink, two sources). Source L7 (`fields`; L8 `sortDir` should be mentioned), sink L9. |
| `safe-parameterized.js` | better-sqlite3 `?` binding, plus an allowlisted sort column and a `parseInt`'d limit interpolated into the SQL | **0 findings.** The interpolated values are allowlisted or numeric, and user input only reaches the query as a bound `?` parameter. |

Scored against these expectations, a run passes when it reports the right number of findings and the right source and sink lines (±1 for statements spanning several lines).
