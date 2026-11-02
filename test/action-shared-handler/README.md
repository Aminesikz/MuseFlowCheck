One Express handler with two findings: `GET /search` builds SQL from `req.query.q` (SQL injection, line 9) and echoes
`q` into HTML (reflected XSS, line 11). Each finding's suggested fix rewrites the whole handler, so the fixes must be
combined. Used by `test/action.test.ts` to check that both inline comments, the summary and the CLI cards warn about it.
