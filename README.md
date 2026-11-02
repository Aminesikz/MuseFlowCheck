# Flowcheck

Flowcheck is an AI agent for shift-left secure-code review of JavaScript/TypeScript. It uses LLM-driven, cross-file taint analysis to trace untrusted input from sources to dangerous sinks across a codebase, then runs a self-verification pass on each finding to cut false positives before reporting. It ships as a CLI and a [GitHub Action](#github-action), built on Meta's Model API (Muse Spark).

Intentionally built for the Meta Global AI Developer Hackathon.

**Status:** WIP — SQL injection, broken access control / IDOR, and cross-site scripting (reflected and stored, server and React): project-wide scanning with cross-file tracing, model judgment, and optional self-verification that proves findings against a running local target.

## Quick start

```bash
cp .env.example .env   # then paste your META_API_KEY into .env
npm install
npm run smoke          # check API access
npm run build
node dist/cli.js scan path/to/project          # whole project: SQL injection, access control and XSS in one pass
node dist/cli.js scan path/to/project --json   # { "findings": Finding[], "analysis": {...} } on stdout
```

`flowcheck scan <dir>` runs every vulnerability class by default and reports one merged result; `--mode sqli`, `--mode access` or `--mode xss` narrows it to one. It exits `0` when there are no high/critical findings and the analysis was complete, `1` when there are high/critical findings, `2` on errors (including a sink the model could not judge), and `3` when the analysis was incomplete (see below). A high/critical finding takes precedence over an error, and an error over an incomplete analysis.

### Incomplete analysis

"No findings" is only a clean result if the engine actually followed the code. A scan is **incomplete** when more than 20% of any of these went unanalyzed:

- **routes:** registrations naming project code (`app.get('/x', mw, handler)`) whose handler or any middleware could not be resolved;
- **tainted calls:** calls into project code the tracer could not follow, counted over all classes, and also within each class, so one class whose traces all broke is not hidden by the others;
- **files:** source files with syntax errors.

A project with no route or handler at all is also incomplete: nothing was analyzed. An incomplete scan exits `3` instead of `0` and ends with a warning that names what was not followed and why (each reason with a count, the functions or classes it was about, and an example location). The summary always carries an `Analysis:` row, `complete` or `INCOMPLETE`. Tune the threshold with `--max-unresolved <percent>` (or `maxUnresolved` in the config file); `100` accepts any coverage. This only changes the verdict — what is traced and judged is the same either way.

### Configuration

Settings you would otherwise repeat on every command — the verification target, its token, and the token's identity — can live in a `museflowcheck.config.json`:

```bash
cp museflowcheck.config.example.json museflowcheck.config.json   # then fill in target, token, identity
node dist/cli.js scan ../MetaVulnSite/server                     # full combined scan, verified against the configured target
```

```json
{
  "target": "http://localhost:4000",
  "token": "<a seeded low-privilege tenant token>",
  "identity": "it belongs to shop 1"
}
```

- **Where it is read from:** the scanned directory, then its project root (the nearest `package.json`), then the current directory. The first file found is used.
- **Keys:** `target`, `token`, `identity`, `mode`, `maxUnresolved`, `probeRange`, `loginPath`, `loginBody`, `tokenField`, `browserPath`, `xssClient`, `xssTokenStore`, `startCmd`, `readyPath` — each means the same as its flag. An unknown key is an error, so a typo never silently drops a setting.
- **Environment variables:** every key also has a `MUSEFLOWCHECK_<NAME>` variable — `MUSEFLOWCHECK_TARGET`, `MUSEFLOWCHECK_TOKEN`, `MUSEFLOWCHECK_IDENTITY`, `MUSEFLOWCHECK_PROBE_RANGE`, …
- **Precedence:** a flag on the command line wins over the environment, which wins over the file. A `--login-path` given at a higher level replaces a token from a lower one.
- **Secrets:** `museflowcheck.config.json` is gitignored because it holds a token; only the `.example` file is committed. The token is never printed: the scan names which settings came from the file or the environment, never their values, and any occurrence of the token in the human output is shown as `[token]`.

### Output

On a terminal, each finding is a card: a color-coded severity badge (`[CRITICAL]` red, `[HIGH]` yellow, `[MEDIUM]` blue, `[LOW]` dim), the type and CWE, and `✓ exploit confirmed` when verification proved it. Under it come the route and `source file:line → sink file:line`, the taint path hop by hop, the **Inputs** when several reach the same sink (see below), **Why** it is exploitable, the **Proof** (what the exploit demonstrated, when confirmed), and the suggested **Fix** as a code block. When other findings' fixes rewrite the same handler or function, a **⚠ Fix together** note above the fix names them: each patch fixes only its own finding, so they must be combined. A summary closes the report, with counts per class, per severity and per confidence.

**Several inputs into one sink.** When Stage 1 traced more than one request input into the same sink — two query parameters concatenated into one SQL string, two values written unencoded into one HTML output, two request identifiers selecting rows of the same table with no owner check — the judge is shown each of them and asked which are exploitable. The finding stays one finding (one vulnerability, several vectors): its JSON carries `vectors` (each input with where it enters, its route and its own taint path; the input `taintPath` shows comes first), the explanation names every input, and the suggested patch must close all of them, not only the one in `taintPath`. Detection, severity and verification are unchanged: one confirmed exploit through any input confirms the finding. A sink one input reaches gets exactly the prompt and the finding it did before, with no `vectors` field. Identifiers into different tables are separate accesses and never become vectors of each other.

To check that a scan's patches close every input, offline (no model call, nothing modified):

```bash
npx tsx scripts/check-patch-vectors.ts scan.json <scanned dir>   # applies each patch to a copy, re-runs Stage 1, lists inputs still open
```

Color is used only on a terminal. It is off when output is piped, with `--json`, when `NO_COLOR` is set, or with `--no-color` (`FORCE_COLOR=1` turns it on anyway); without color every status is still a label or symbol. `--json` is the machine interface: stdout carries only `{ "findings": Finding[], "analysis": {...} }`, unchanged by any of the above, while progress and the summary go to stderr. `analysis` reports coverage — `complete`, `entryPointsTotal`, `entryPointsResolved`, `callsFollowed`, `unresolved`, `files`, `filesParsed`, `parseErrors`, `reasons` and `problems` — so a consumer can tell an incomplete scan from a clean one instead of reading `findings: []` as safe.

### SQL injection (project scan)

`flowcheck scan <dir> --mode sqli` runs in two stages:

1. **Discover files and entry points.** Flowcheck loads every JS/TS source file under the directory. It honors `.gitignore` and skips `node_modules`, build output (`dist`, `build`, `coverage`, …) and tests (`test/`, `__tests__/`, `*.test.*`, `*.spec.*`). Entry points are:
   - functions registered on a router or app (`router.get('/x', fn)`, `app.use(mw)`, `router.post('/x', ctrl.save)`), including `bind(...)`, wrappers such as `asyncHandler(fn)`, and arrays of handlers;
   - handlers called by convention, which read `req`/`ctx` input without being registered.
2. **Trace and judge.** Request input (`req.query|params|body`, Koa `ctx.query` / `ctx.request.body`) is traced from every entry point across files to SQL-executing calls, including when the whole request object is passed to a service. Paths are deduplicated across entry points. Each SQL execution call reached through SQL text is judged once by the model, however many routes lead to it.

   A sink is a call that executes a SQL string — recognized by that shape, across database libraries. The execute calls of the common drivers are known instances (illustrative, not exhaustive): node-postgres `pool.query` / `client.query`; mysql / mysql2 `query` / `execute`; better-sqlite3 `db.prepare(sql).run|get|all` and `db.exec`; sqlite3 `db.run|get|all|each`; mssql `request.query`; `knex.raw` and the `…Raw` builder methods, `sequelize.query`, postgres.js `sql.unsafe`, Prisma `$queryRawUnsafe` / `$executeRawUnsafe`. Names that also mean something else (`prepare`, `exec`, `run`, `get`, `all`, …) count only when their first argument is SQL text, so `map.get(id)` or `regex.exec(s)` never do. Input that reaches only bound parameters — any placeholder style: `$1`, `?`, `:name`, `@name` declared with `request.input` — or a query builder's bound values is never sent to the model.

   The suggested patch binds values the way the code's own library does: Stage 1 reads the database package behind each SQL call (from the object the call is made on, else the file's imports), and the judge is told its binding style — `$1, $2` for PostgreSQL drivers, `?` with a values array for MySQL and SQLite, `@name` with `request.input` for SQL Server, bindings or replacements for knex and Sequelize. The access-control and XSS tracers keep their own SQL calls (`query` / `execute`) unchanged.

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

Routes that are unauthenticated, already checked, or that only touch tables the schema shows as unowned are not sent to the model. Each remaining route is judged once, with its evidence and the sibling routes that do enforce a check. Only a route with all three signals (identity available, scoped data, no check) is reported. Reads are reported as IDOR (CWE-639), writes as missing authorization (CWE-862). Severity is an ordered rule on the actor's reach, read from the schema rather than left to the model: **critical** when the unchecked access crosses an ownership boundary — the request value selects rows the schema ties to an owner (an ownership column) or a scope record itself, so the caller reads or changes another user's or tenant's records — and **high** when the code does not establish that it does (no schema shows the rows are owned). The model may only lower that level, with a reason shown in the code.

### Cross-site scripting (reflected)

```bash
node dist/cli.js trace <dir> --mode xss                 # Stage 1 only: every HTML or DOM output request input reaches, no API call
node dist/cli.js trace <dir> --mode xss --show-prompt   # ...plus the Stage 2 prompt for each raw output
node dist/cli.js scan <dir> --mode xss                  # Stage 1 + Stage 2
```

XSS uses the same cross-file tracer as SQL injection, with a different sink: request input placed into a string whose literal text is HTML (a template literal or `+` concatenation containing tags or entities), or written to the response as-is (`res.send(x)`). What matters is whether the value is encoded on the way to that output, so Stage 1 classifies each one:

- **Raw:** the input arrives as text — directly, or through string operations and helpers that return it unchanged. Sent to the model.
- **Encoded:** the input passed a step that HTML-encodes it — a `.replace` that maps `<` to an entity (directly or through a lookup table or callback), or an encoding/sanitizing package (`escape-html`, `he`, `sanitize-html`, DOMPurify, lodash `escape`, …). Listed, never sent. Encoders are recognized by what the code does, not by name: a helper called `escape` that only trims is still raw.
- **Already markup:** HTML built earlier and passed on (to a layout, to `res.send`) is not a new output; the place it was built is where the input was judged.

**Server-side templates.** `res.render(view, data)` places each value of `data` wherever the view's template outputs it. Stage 1 reads the engine from the code (`app.engine`, `app.set("view engine")`, else the project's dependencies), the views directory (`app.set("views")`), and any escaping configured in code (`swig.setDefaults({ autoescape: false })`, nunjucks' `autoescape`, handlebars' `noEscape`). Each output in the template is then raw or escaped by its own syntax: in swig / nunjucks / twig, `{{ x }}` follows the auto-escaping setting (on by default), `|safe` and `{% autoescape false %}` bypass it and `|escape` forces it; in EJS `<%- x %>` is raw and `<%= x %>` escaped; in handlebars / mustache `{{{ x }}}` is raw and `{{ x }}` escaped; in pug `!{x}` / `!=` are raw and `#{x}` / `=` escaped. A tainted value in a raw output is sent to the model, with the template line as the last hop; one in an escaped output is listed as encoded. A view whose template cannot be found, or whose engine is not recognized, is an unresolved call — never assumed safe.

Numbers (`Number(x)`) and JSON responses are not HTML outputs. Each raw output is judged once, together with any encoded outputs of the same input for contrast; the judge confirms hop by hop that no encoding occurs and proposes a patch that encodes at the output.

**Execution proof (optional).** With a local `--target` and a headless browser, an XSS finding is proved the same way SQLi and IDOR are: the model generates a payload carrying a fresh unique marker, and the tool renders the vulnerable page in the browser and confirms the marker fires only on the exploit, never on a benign baseline. Reflected findings load the parameterized URL; stored findings write the payload through the write route, load the rendering page, then **restore the original value** (reporting a re-seed if it cannot). The browser is driven through `puppeteer-core` — a dev/verification-only dependency that uses an already-installed Chrome and is loaded dynamically, so it never enters the core CLI's required dependencies. Without a browser (or without `--target`), XSS findings stay `"suspected"`; verification never lowers a finding on its own. Flags: `--browser-path`, `--xss-client <local-url>` (for sinks rendered by a client app), `--xss-token-store`.

**Stored XSS** spans two requests, so the trace runs in two passes. The first records which database column each SQL write (`UPDATE … SET col = $1`, `INSERT INTO t (col) VALUES (?)`) fills from raw request input. The second treats every read of such a column (`SELECT`, `RETURNING`) as a source — only that property of the returned rows is tainted, so `post.body` is a candidate while a column the app never writes from input is not — and follows it to outputs on any route, including routes with no request input of their own. Its path shows the write (up to `[store]`), where the rendering request begins (`[entry]`) and reads the value back (`[load]`), and how it reaches the output.

**Browser code** — files of a package that depends on a UI library such as React — is walked after the server: a stored value the server sends as JSON is what `fetch` (or an HTTP client package) returns there, and it is followed through `useState` setters, component props and promise callbacks. In the browser, only DOM HTML sinks are outputs: `dangerouslySetInnerHTML`, `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`. A JSX text child (`<p>{text}</p>`) is escaped by React, so it is listed, never sent. Scan the directory that contains both the server and the client to connect them.

Findings are reported as `Cross-Site Scripting (Reflected)` or `Cross-Site Scripting (Stored)` (CWE-79). Severity is an ordered rule on who receives the output, read from the handler of the route that renders or serves a stored value: **critical** when stored input reaches viewers beyond the writer's own scope (the handler reads no authenticated identity, or reads one without restricting the record to it), **high** when it reaches only the scope that owns the record, or when it is reflected (a victim must open a crafted link). The model may only lower that level, with a reason shown in the code.

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
- Constructor functions: `new F(db)` on a plain function whose members are `this.m = …` (arrow or function expression) or `F.prototype.m = …`; `instance.m(...)` resolves to that member, and `this` inside it is the instance. Handlers, middleware (`const isLoggedIn = session.isLoggedInMiddleware`) and data-access objects written this way are followed like class instances. `new` on a function that sets no members stays unresolved.
- Destructured parameters, mapped by key when the argument is an object literal.

A tainted call that can't be followed is listed, never dropped. The trace output shows it either as **unresolved** (project code the tracer couldn't follow, such as a dynamic `require`, a missing export, or taint passed into a constructor and stored in a field) or as **leaving the project** (a package, a global, or a caller-supplied parameter).

## GitHub Action

The Action runs the combined scan on every pull request, posts each finding as a review comment on the diff, and fails the check on high/critical findings **or an incomplete analysis**. It wraps the CLI: `scan <path> --json`, whose `{ findings, analysis }` and exit code it maps onto GitHub. It does no detection of its own.

### Setup

1. Add the model key as a repository secret named `META_API_KEY` (Settings → Secrets and variables → Actions).
2. Copy [`examples/museflowcheck.yml`](examples/museflowcheck.yml) to `.github/workflows/museflowcheck.yml`:

```yaml
name: MuseFlowCheck
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write # inline review comments and the summary comment
jobs:
  museflowcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: Aminesikz/MuseFlowCheck@main
        with:
          api-key: ${{ secrets.META_API_KEY }}
```

3. To block merges on a failing scan, require the `museflowcheck` check in the branch's protection rule (Settings → Branches → require status checks to pass). The check takes its name from the job id, and it can be selected once it has run at least once.

The Action checks out the PR's head commit, builds MuseFlowCheck, and scans the whole repository: cross-file taint needs the whole project, so a PR that only edits a helper still gets the flows through it.

### What it posts

- **Inline review comments**, one per finding that touches the PR's changed files. A comment goes on the sink line if the diff includes it, else the source line, else any taint-path hop in the diff (so a PR that edits a function in the middle of a flow gets the finding). If the file changed but none of those lines is in the diff, the comment goes on the file. Each comment has a severity badge, the type and CWE, the route with source → sink, the taint path, why the flow is exploitable, and the suggested fix.
- **Findings elsewhere in the repository** are not commented inline: GitHub only accepts review comments on the diff, and existing findings would flood the PR. They are still counted, listed in the summary, and gate the check.
- **One summary comment**, with the verdict, findings by class and severity, and analysis coverage. A later run updates it in place. The same report goes to the job summary.
- **Findings whose fixes overlap are flagged.** When two or more findings' suggested fixes rewrite the same route handler or function (a SQL injection and an XSS in one handler, say), each patch fixes only its own finding. Applied alone it leaves the other bug in place, and applied one after another the patches conflict. Each such comment carries a "⚠ Fix together" warning naming the other findings, and the summary groups them. The patches are not merged automatically: combine them into one fix.
- **Re-runs do not repost.** Each comment carries a hidden fingerprint: the finding's class and its taint path without line numbers. A finding already on the PR is skipped, even when a push only moved its code. A changed flow is a new finding and gets a new comment. A comment already posted is edited only when its "Fix together" warning changes, because a finding sharing its fix appeared or went away.

Without a pull request (a `push` or a manual run), or when the token cannot write comments (a PR from a fork gets a read-only token), findings are reported as annotations on the commit instead.

### Check status

| Engine result | `status` output | Check |
|---|---|---|
| Analysis complete, nothing at or above `fail-on` (exit `0`) | `pass` | ✅ green |
| A finding at or above `fail-on` (exit `1`) | `findings` | ❌ failed — merge blocked |
| Analysis incomplete (exit `3`), no gating finding | `incomplete` | ❌ failed — **INCOMPLETE ANALYSIS — not a clean bill of health** |
| Engine error (exit `2`), unreadable output, or any other exit | `error` | ❌ failed |

An incomplete scan never gets a green check, whatever `fail-on` is set to. The engine's exit `1` takes precedence over `3`, so the Action also reads `analysis.complete` from the JSON: when a scan has findings and is also incomplete, the summary reports both. The incomplete-analysis report lists what could not be followed and why, as the CLI's warning does. To accept lower coverage, raise `max-unresolved` (`100` accepts any). To make the check non-blocking without making it green, leave it out of the branch's required status checks: it stays red and visible.

### Inputs

| Input | Default | |
|---|---|---|
| `api-key` | — (required) | Meta Model API key, from a secret |
| `path` | `.` | Directory to scan, relative to the repository root |
| `fail-on` | `high` | Lowest severity that fails the check: `critical`, `high`, `medium`, `low`, or `none` |
| `max-unresolved` | engine default (`20`) | Percent of routes, tainted calls or files that may go unanalyzed before the scan is incomplete |
| `inline-comments` / `summary-comment` | `true` | Turn either kind of comment off |
| `max-comments` | `25` | Most new inline comments per run; the rest are listed in the summary |
| `checkout` | `true` | Set to `false` if the workflow already checked out the code |
| `base-url` / `model` | `https://api.meta.ai/v1` / `muse-spark-1.3` | Model endpoint |
| `github-token` | `github.token` | Needs `pull-requests: write` |
| `target` / `target-token` | — | Advanced: verification (below) |

Outputs: `status` (`pass`, `findings`, `incomplete` or `error`), `findings`, `gated` (findings at or above `fail-on`), and `complete`.

### Detection only by default; verification is opt-in

A PR gate reviews a diff, not a running deployment, so the Action passes no `--target` by default. Findings are `suspected` and nothing is executed. To prove findings in CI, start the app on the runner earlier in the job, then pass its **local** URL:

```yaml
      - run: docker compose up -d && npx wait-on http://localhost:4000
      - uses: Aminesikz/MuseFlowCheck@main
        with:
          api-key: ${{ secrets.META_API_KEY }}
          target: http://localhost:4000
          target-token: ${{ secrets.MUSEFLOWCHECK_TARGET_TOKEN }} # a seeded low-privilege account
        env:
          MUSEFLOWCHECK_IDENTITY: it belongs to shop 1 # any other setting, as MUSEFLOWCHECK_<NAME>
```

The engine also reads a `museflowcheck.config.json` committed in the scanned project (see [Configuration](#configuration)). A `target` set there turns verification on as well.

### Notes

- **Forks:** workflows triggered by a PR from a fork get no secrets, so the scan fails with a "no API key" error rather than passing. Keep the `pull_request` trigger; don't switch to `pull_request_target` to get around this.
- **Cost:** each run makes one model call per judged sink or route, as the CLI does.
- **Trying it locally:** `scripts/action-demo.ts` runs the Action's runner against a project, with a stand-in GitHub API that records the comments it would post. The stand-in rejects comments GitHub would reject. It prints the comments, the summary, the step outputs and the exit code:

```bash
npx tsx scripts/action-demo.ts test/project-scan --changed controllers/reports.js --offline   # canned model replies
npx tsx scripts/action-demo.ts test/action-incomplete --offline                               # incomplete: fails, not green
npx tsx scripts/action-demo.ts test/project-scan --changed controllers/reports.js            # real model, META_* from .env
```

`npx tsx --test test/action.test.ts` covers the verdict, the anchoring and the payloads offline.

## Verification (proving findings)

Analysis reports findings as `"suspected"`. When you pass `--target`, Flowcheck tries to prove each finding by executing it against a running instance you control, and marks it `"confirmed"` or `"unverified"`.

> **Safety.** Verification sends real exploit requests, so it runs **only** against a loopback target you configure explicitly — `localhost`, `127.0.0.1`, `::1`, or a `*.localhost` / `*.test` host. Any other host is refused. There is no host discovery; without `--target`, verification never runs and behavior is exactly as before.

For each finding the model proposes a benign **baseline** request and an **exploit** request, plus a success condition the tool checks by comparing the two real responses (a tenant of injected rows the baseline doesn't return, a UNION marker, a cross-tenant field, an unblocked status, or a body difference — see below). A finding is only `"confirmed"` when that comparison shows the exploit did something the baseline did not; otherwise it is `"unverified"` and says so.

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

**Session-cookie apps.** Apps that keep the login in a session cookie (`express-session` and similar) can be exploit-proven too. With `--auth session --login-path /auth/login --login-body '{"username":"…","password":"…"}'`, Flowcheck posts the credentials once, captures the `Set-Cookie` from the response (a `2xx` or a `302` after login both count), and sends that cookie on every baseline and exploit request. `--cookie "<name=value; …>"` (or `--auth cookie`) uses a cookie you already have. A login that sets no cookie is reported as a configuration error. Bearer tokens remain the default; a bearer target never sends or stores cookies. Both settings can also go in the config file (`auth`, `cookie`).

**Body difference.** Some exploits prove themselves only in the page content: an authentication bypass answers `200` either way, but the exploit's page says "welcome" where the wrong-credentials baseline says "wrong password". The PoC can name such a server success phrase, and the finding confirms only if that phrase is in the exploit response, absent from the baseline's, not the exploit's own input reflected back, and a stable phrase rather than a timestamp, id or token. A difference that is only noise never confirms.

With `--verify-patch`, a confirmed finding's `suggestedPatch` is applied to a throwaway copy of the project (the original is never touched), the copy is started (`--start-cmd`, default `npm start`), and the exact PoC is re-run: the patch is `blocked` only if the exploit now fails **and** the benign request returns the same response as before the patch (same status, same body). If the exploit fails but the benign response changed, the patch is reported as `breaks-route`; if the exploit still works, `still-exploitable`. When the benign response was empty, a `blocked` result says so, since it then shows the route answers the same way rather than that real results are unchanged. Patches that aren't a clean single-function replacement are reported as `not-attempted` rather than guessed at.

## Validation on third-party code

Beyond the bundled fixture, Flowcheck was run (detection only, no `--target`) against [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Node/Express app neither written for nor tuned to this tool. NodeGoat's own tutorial was used only to know what should be found, not as input to detection.

- **Coverage:** 27 files, 22 of 22 routes and every tainted call followed, 0 unresolved; the analysis is complete. A first run, before old-style constructor functions were supported, followed 4 of 22 routes — and correctly reported itself as incomplete (exit `3`) rather than clean.
- **Found:** 12 reflected XSS (NodeGoat A3) in `POST /login`, `POST /signup`, `POST /profile` and `GET /allocations/:userId`: request input rendered into swig templates with auto-escaping disabled (`swig.setDefaults({ autoescape: false })`). Each finding names that setting as the root cause and proposes escaping at the template output. They are `suspected` (not live-verified: NodeGoat was not run).
- **Not found:** NodeGoat's access-control bugs (A4 IDOR on `/allocations/:userId`, A7 missing admin check on `/benefits`) and its stored XSS (A3's stored profile fields, A9 via `marked`) — all go through MongoDB, which is out of scope (see below). Most of NodeGoat's other intentional bugs (server-side `eval`, NoSQL injection, CSRF, open redirect, SSRF, ReDoS, auth and configuration issues) are classes Flowcheck does not cover.

## Known limitations / roadmap

- **NoSQL / MongoDB is not supported yet.** Access-control and stored-XSS detection follow SQL data access: access mode ties a request value to a table and column through the SQL statement and the schema, and stored XSS follows a value written by a SQL write and read back by a SQL read. MongoDB `collection.find()` / `insert()` / `update()` calls are not recognized as data access. The tracer reaches those routes, but no data access is found on them — so on NodeGoat this blocks A4 (IDOR), A7 (missing authorization) and A9 (stored XSS via `marked`). Roadmap.
- **Session-only middleware does not establish an identity.** Access mode looks for middleware that sets an identity (`req.user = …`, `ctx.state.user = …`). Middleware that only checks `req.session` (`if (req.session.userId) next()`), NodeGoat's pattern, resolves and is on the route's chain, but is not treated as establishing the caller's scope. Roadmap.
- **A library call can be misread as a route.** Route discovery counts `.get` / `.post` / … calls on any object that is not project code, so an HTTP client call like `needle.get(url, callback)` is listed as a `GET` route (one phantom entry point on NodeGoat; it reads no request input, so nothing is judged on it). Telling a client library apart from an Express app or router needs more than a one-line check, so it is left as a known issue.
- **Deleted or created records are not restored.** A write proof restores what it changed, but a `DELETE` (or a `POST` that creates a record) cannot be undone automatically: the finding then says `RE-SEED RECOMMENDED`. The same applies to a stored-XSS proof whose original value could not be restored.
- **Body-difference confirmation depends on the model naming the success phrase.** The PoC is generated blind (the model never sees the target's responses), so for a localized or non-English app it may not guess the exact phrase the server prints on success. A genuine exploit is then honestly reported `unverified`, never falsely confirmed (on sc_pro, a Korean-language app, the login bypass stayed `unverified` this way). Roadmap: derive the expected response indicators from the handler's response source, for language-agnostic confirmation.
- **Node's built-in `node:sqlite` driver is not recognized yet.** SQL sinks are recognized by their package (`pg`, `mysql2`, `better-sqlite3`, `sqlite3`, …). `DatabaseSync` from Node's own `node:sqlite` (`db.prepare(sql).all()`, `db.exec(sql)`) is not in that list, so injection into a query run through it is missed. Roadmap.
- **Taint through instance fields is not tracked.** A value stored on an object (`this.query = req.query.q`, or a tainted constructor argument kept in a field) and read later by another method is not followed; the constructor call is listed as unresolved, never dropped.

## License

[MIT](LICENSE)
