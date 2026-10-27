# Flowcheck

Flowcheck is an AI agent for shift-left secure-code review of JavaScript/TypeScript. It uses LLM-driven, cross-file taint analysis to trace untrusted input from sources to dangerous sinks across a codebase, then runs a self-verification pass on each finding to cut false positives before reporting. It will ship as a CLI and a GitHub Action, built on Meta's Model API (Muse Spark).

Intentionally built for the Meta Global AI Developer Hackathon.

**Status:** WIP — SQL injection only: project-wide scanning with cross-file tracing and model judgment (no self-verification pass yet).

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

## License

[MIT](LICENSE)
