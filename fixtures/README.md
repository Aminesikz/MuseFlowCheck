# Fixtures

Intentionally vulnerable code for testing Flowcheck. Do not deploy. Fixture files carry no hint comments, so the model has to find the issues from the code alone. The expected results are listed here instead.

| File | Expected |
| --- | --- |
| `sqli-single-file.js` | 1 SQL Injection (CWE-89): source L8 (`req.query.name`), SQL built on L9, sink L10 (`pool.query`, the execute call). The `/users/:id` route is parameterized and must **not** be reported. |
