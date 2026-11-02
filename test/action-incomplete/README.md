NodeGoat-style project whose route handlers and data access are loaded through computed `require()` paths. The
tracer cannot follow them, so a scan of it is **incomplete** (exit 3) — the SQL injection in the data layer goes
unseen, and "no findings" must not read as a pass. Used by `test/action.test.ts` to check the GitHub Action never
reports a green check for it.
