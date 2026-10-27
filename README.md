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

## License

[MIT](LICENSE)
