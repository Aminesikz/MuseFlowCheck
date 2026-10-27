# Flowcheck

Flowcheck is an AI agent for shift-left secure-code review of JavaScript/TypeScript. It uses LLM-driven, cross-file taint analysis to trace untrusted input from sources to dangerous sinks across a codebase, then runs a self-verification pass on each finding to cut false positives before reporting. It will ship as a CLI and a GitHub Action, built on Meta's Model API (Muse Spark).

Intentionally built for the Meta Global AI Developer Hackathon.

**Status:** WIP — single-file SQL injection detection (no cross-file tracing or verification yet).

## Quick start

```bash
cp .env.example .env   # then paste your META_API_KEY into .env
npm install
npm run smoke          # check API access
npm run build
node dist/cli.js scan fixtures/sqli-single-file.js
```

`flowcheck scan <file>` exits `0` when there are no high/critical findings, `1` when there are, and `2` on errors.

### Cross-file (spike)

```bash
node dist/cli.js trace <route-file>                 # Stage 1: deterministic call-graph taint trace, no API call
node dist/cli.js trace <route-file> --show-prompt   # ...plus the Stage 2 prompt that would be sent
node dist/cli.js scan <route-file> --cross-file     # Stage 1 + Stage 2 (model judges each traced SQL sink)
```

The project root defaults to the nearest folder with a `package.json`; override it with `--root <dir>`.

Calls are resolved syntactically across CommonJS and ES modules:

- `require` / `import`: namespace, default, named, aliased, destructured, and `require('./x').fn`.
- Re-exports: barrel `index` files, `module.exports = { ...require('./x') }`, `export { x } from`, `export { default } from`, and `export * from`.
- Methods on exported objects, class instances (including `this.method()`), and objects returned by single-return factories.
- Handlers defined in another file and registered by reference (`router.get('/x', controller.list)`).
- Destructured parameters, mapped by key when the argument is an object literal.

A tainted call that can't be followed is listed, never dropped. The trace output shows it either as **unresolved** (project code the tracer couldn't follow, such as a dynamic `require`, a missing export, or a constructor-injected dependency) or as **leaving the project** (a package, a global, or a caller-supplied parameter).

## License

[MIT](LICENSE)
