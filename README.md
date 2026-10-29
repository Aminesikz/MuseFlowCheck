# Flowcheck

Flowcheck is an AI agent for shift-left secure-code review of JavaScript/TypeScript. It uses LLM-driven, cross-file taint analysis to trace untrusted input from sources to dangerous sinks across a codebase, then runs a self-verification pass on each finding to cut false positives before reporting. It will ship as a CLI and a GitHub Action, built on Meta's Model API (Muse Spark).

Intentionally built for the Meta Global AI Developer Hackathon.

**Status:** WIP — SQL injection, broken access control / IDOR, and reflected cross-site scripting: project-wide scanning with cross-file tracing, model judgment, and optional self-verification that proves findings against a running local target.

## Quick start

```bash
cp .env.example .env   # then paste your META_API_KEY into .env
npm install
npm run smoke          # check API access
npm run build
node dist/cli.js scan path/to/project          # whole project
node dist/cli.js scan path/to/project --json   # findings as a JSON Finding[] on stdout
```

`flowcheck scan` exits `0` when there are no high/critical findings, `1` when there are, and `2` on errors (including a sink the model could not judge).

### Project scan

`flowcheck scan <dir>` runs in two stages:

1. **Discover files and entry points.** Flowcheck loads every JS/TS source file under the directory. It honors `.gitignore` and skips `node_modules`, build output (`dist`, `build`, `coverage`, …) and tests (`test/`, `__tests__/`, `*.test.*`, `*.spec.*`). Entry points are:
   - functions registered on a router or app (`router.get('/x', fn)`, `app.use(mw)`, `router.post('/x', ctrl.save)`), including `bind(...)`, wrappers such as `asyncHandler(fn)`, and arrays of handlers;
   - handlers called by convention, which read `req`/`ctx` input without being registered.
2. **Trace and judge.** Request input (`req.query|params|body`, Koa `ctx.query` / `ctx.request.body`) is traced from every entry point across files to SQL-executing calls, including when the whole request object is passed to a service. Paths are deduplicated across entry points. Each SQL execution call reached through SQL text is judged once by the model, however many routes lead to it.

```bash
node dist/cli.js trace <dir>                  # Stage 1 only: entry points, every traced hop, unresolved calls; no API call
node dist/cli.js trace <dir> --show-prompt    # ...plus the Stage 2 prompt for each SQL sink
```

### Broken access control / IDOR

```bash
node dist/cli.js trace <dir> --mode access                  # Stage 1 only: per-route evidence, no API call
node dist/cli.js scan <dir> --mode access                   # Stage 1 + Stage 2
node dist/cli.js scan <dir> --mode access --route /orders   # judge only routes whose "METHOD /path" contains /orders
```

An access-control bug is a missing check, not a dangerous sink: the query can be perfectly parameterized. For each route (paths composed from where routers are mounted), Stage 1 assembles evidence instead of hunting sinks:

- **Request identifiers → data:** which path parameters (and `…Id`-style query/body fields) reach which data access, read or write, and which column they select.
- **Identity:** the middleware on the route's chain that sets `req.user` (or `ctx.state.user`), and the fields it carries.
- **Scoping:** from SQL schema files, which accessed tables carry an ownership column (`<identity field>` in snake case, usually a foreign key) or are themselves the scope record.
- **Checks:** comparisons of a request value or a loaded record's owner field with the identity that reject on mismatch (in the handler, services or middleware), and queries constrained by an identity value. A check placed after a write does not count.

Routes that are unauthenticated, already checked, or that only touch tables the schema shows as unowned are not sent to the model. Each remaining route is judged once, with its evidence and the sibling routes that do enforce a check. Only a route with all three signals (identity available, scoped data, no check) is reported. Reads are reported as IDOR (CWE-639), writes as missing authorization (CWE-862).

### Cross-site scripting (reflected)

```bash
node dist/cli.js trace <dir> --mode xss                 # Stage 1 only: every HTML output request input reaches, no API call
node dist/cli.js trace <dir> --mode xss --show-prompt   # ...plus the Stage 2 prompt for each raw output
node dist/cli.js scan <dir> --mode xss                  # Stage 1 + Stage 2
```

XSS uses the same cross-file tracer as SQL injection, with a different sink: request input placed into a string whose literal text is HTML (a template literal or `+` concatenation containing tags or entities), or written to the response as-is (`res.send(x)`). What matters is whether the value is encoded on the way to that output, so Stage 1 classifies each one:

- **Raw:** the input arrives as text — directly, or through string operations and helpers that return it unchanged. Sent to the model.
- **Encoded:** the input passed a step that HTML-encodes it — a `.replace` that maps `<` to an entity (directly or through a lookup table or callback), or an encoding/sanitizing package (`escape-html`, `he`, `sanitize-html`, DOMPurify, lodash `escape`, …). Listed, never sent. Encoders are recognized by what the code does, not by name: a helper called `escape` that only trims is still raw.
- **Already markup:** HTML built earlier and passed on (to a layout, to `res.send`) is not a new output; the place it was built is where the input was judged.

Numbers (`Number(x)`), JSON responses, and values read back from the database are not treated as reflected input. Each raw output is judged once, together with any encoded outputs of the same input for contrast; the judge confirms hop by hop that no encoding occurs and proposes a patch that encodes at the output. Findings are reported as `Cross-Site Scripting (Reflected)` (CWE-79). Verification against a target is not available for XSS yet.

### Single entry file

```bash
node dist/cli.js scan <file>                      # single-file analysis by the model
node dist/cli.js trace <route-file>               # Stage 1 from one entry file, no API call
node dist/cli.js scan <route-file> --cross-file   # Stage 1 + Stage 2 from one entry file
```

For a single entry file, the project root defaults to the nearest folder with a `package.json`; override it with `--root <dir>`.

Calls are resolved syntactically across CommonJS and ES modules:

- `require` / `import`: namespace, default, named, aliased, destructured, and `require('./x').fn`.
- Re-exports: barrel `index` files, `module.exports = { ...require('./x') }`, `export { x } from`, `export { default } from`, and `export * from`.
- Methods on exported objects, class instances (including `this.method()`), and objects returned by single-return factories.
- Constructor-injected dependencies: `this.repo = repo`, TypeScript parameter properties, and `super(...)` chains, resolved from the `new` site's arguments.
- Handlers defined in another file and registered by reference (`router.get('/x', controller.list)`).
- Destructured parameters, mapped by key when the argument is an object literal.

A tainted call that can't be followed is listed, never dropped. The trace output shows it either as **unresolved** (project code the tracer couldn't follow, such as a dynamic `require`, a missing export, or taint passed into a constructor and stored in a field) or as **leaving the project** (a package, a global, or a caller-supplied parameter).

## Verification (proving findings)

Analysis reports findings as `"suspected"`. When you pass `--target`, Flowcheck tries to prove each finding by executing it against a running instance you control, and marks it `"confirmed"` or `"unverified"`.

> **Safety.** Verification sends real exploit requests, so it runs **only** against a loopback target you configure explicitly — `localhost`, `127.0.0.1`, `::1`, or a `*.localhost` / `*.test` host. Any other host is refused. There is no host discovery; without `--target`, verification never runs and behavior is exactly as before.

For each finding the model proposes a benign **baseline** request and an **exploit** request, plus a success condition the tool checks by comparing the two real responses (a tenant of injected rows the baseline doesn't return, a UNION marker, a cross-tenant field, or an unblocked status). A finding is only `"confirmed"` when that comparison shows the exploit did something the baseline did not; otherwise it is `"unverified"` and says so.

```bash
# start the target yourself (example: the bundled vulnerable fixture)
cd ../MetaVulnSite && npm run seed && npm start      # prints seeded per-tenant bearer tokens

# SQL injection, proved as a low-privilege tenant:
node dist/cli.js scan ../MetaVulnSite/server \
  --target http://localhost:4000 --token <seeded-tenant-token> --identity "it belongs to shop 1"

# Broken access control / IDOR:
node dist/cli.js scan ../MetaVulnSite/server --mode access \
  --target http://localhost:4000 --token <seeded-tenant-token>
```

For a `:id`-style IDOR (`GET`/`PATCH /api/orders/:id`), a victim id picked at random often belongs to the caller's own scope, so the exploit and baseline look identical and nothing is proved. Flowcheck instead **discovers** a cross-scope id the way an attacker would: it requests the `:id` endpoint across a small bounded range as the authenticated caller (`--probe-range`, default 20) and takes the first id whose owner/scope field differs from the caller's own — never reading the seed, the database, or any other source. For a write (`PATCH`/`PUT`/`DELETE`), it snapshots the foreign resource, performs the cross-scope change, reads it back to show it took effect, then restores it; if a change can't be reverted automatically it says a re-seed is recommended. The own-scope baseline is a no-op write of the resource's current values, so your own data is never altered.

Instead of `--token`, you can pass `--login-path /api/auth/login --login-body '{"email":"…","password":"…"}'` and Flowcheck exchanges the credentials for a token (`--token-field` names the field, default `token`).

With `--verify-patch`, a confirmed finding's `suggestedPatch` is applied to a throwaway copy of the project (the original is never touched), the copy is started (`--start-cmd`, default `npm start`), and the exact PoC is re-run: the patch is `blocked` only if the exploit now fails **and** the benign request returns the same response as before the patch (same status, same body). If the exploit fails but the benign response changed, the patch is reported as `breaks-route`; if the exploit still works, `still-exploitable`. When the benign response was empty, a `blocked` result says so, since it then shows the route answers the same way rather than that real results are unchanged. Patches that aren't a clean single-function replacement are reported as `not-attempted` rather than guessed at.

## License

[MIT](LICENSE)
