# Fixtures

Intentionally vulnerable code for testing Flowcheck. Do not deploy. Fixture files carry no hint comments, so the model has to find the issues from the code alone. The expected results are listed here instead.

| File | Expected |
| --- | --- |
| `sqli-single-file.js` | 1 SQL Injection (CWE-89): `req.query.name` (line 8) concatenated into SQL and run by `pool.query` (line 10). The `/users/:id` route is parameterized and must **not** be reported. |
