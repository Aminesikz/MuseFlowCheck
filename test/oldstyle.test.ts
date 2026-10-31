// Old-style constructor functions (`function F(db) { this.m = … }` with `new F(db)`), middleware wired through them,
// and server-side templates (`res.render(view, data)`) as an XSS output that honors the engine's escaping.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { assembleAccessContext } from "../src/engine/access/index.js";
import { traceProject } from "../src/engine/crossfile/index.js";
import { traceXssProject } from "../src/engine/xss/index.js";

const tmp = mkdtempSync(path.join(tmpdir(), "flowcheck-oldstyle-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function project(name: string, files: Record<string, string>): string {
  const dir = path.join(tmp, name);
  for (const [file, text] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), text);
  }
  return dir;
}

// Route handlers and a data-access object written as constructor functions, wired in another file — with a
// member arrow, a member function expression calling a sibling through `this`, and a prototype method.
const ctorFiles = {
  "routes/index.js": [
    'const SessionHandler = require("./session");',
    'const TicketHandler = require("./tickets");',
    "module.exports = (app, db) => {",
    "  const session = new SessionHandler(db);",
    "  const tickets = new TicketHandler(db);",
    "  const isLoggedIn = session.isLoggedInMiddleware;",
    '  app.get("/tickets/:id", isLoggedIn, tickets.show);',
    '  app.get("/tickets/search", isLoggedIn, tickets.search);',
    '  app.post("/tickets/close", isLoggedIn, tickets.close);',
    "};",
    "",
  ].join("\n"),
  "routes/session.js": [
    "function SessionHandler(db) {",
    "  this.isLoggedInMiddleware = (req, res, next) => {",
    "    req.user = { id: req.session.userId, teamId: req.session.teamId };",
    "    return req.user.id ? next() : res.redirect('/login');",
    "  };",
    "}",
    "module.exports = SessionHandler;",
    "",
  ].join("\n"),
  "routes/tickets.js": [
    'const { TicketDAO } = require("../data/ticket-dao");',
    "function TicketHandler(db) {",
    "  const dao = new TicketDAO(db);",
    "  this.show = (req, res) => dao.byId(req.params.id).then((rows) => res.json(rows));",
    "  this.search = function (req, res) {",
    "    return this.find(req.query.q, res);",
    "  };",
    "  this.find = (text, res) => dao.search(text).then((rows) => res.json(rows));",
    "  this.close = (req, res) => dao.close(req.body.id).then(() => res.sendStatus(204));",
    "}",
    "module.exports = TicketHandler;",
    "",
  ].join("\n"),
  "data/ticket-dao.js": [
    "const TicketDAO = function (db) {",
    "  this.byId = (id) => db.query('SELECT * FROM tickets WHERE id = $1', [id]);",
    "  this.search = (text) => db.query(\"SELECT * FROM tickets WHERE title LIKE '%\" + text + \"%'\");",
    "};",
    "TicketDAO.prototype.close = function (id) {",
    "  return this.run(\"UPDATE tickets SET closed = true WHERE id = \" + id);",
    "};",
    "TicketDAO.prototype.run = function (sql) {",
    "  return pool.query(sql);",
    "};",
    "const pool = require('pg');",
    "module.exports.TicketDAO = TicketDAO;",
    "",
  ].join("\n"),
  "schema.sql": "CREATE TABLE teams (id SERIAL PRIMARY KEY);\nCREATE TABLE tickets (id SERIAL PRIMARY KEY, team_id INT REFERENCES teams(id), title TEXT, closed BOOLEAN);\n",
};

test("constructor functions: handlers and DAO methods resolve across files, through this.m, this.sibling() and prototype methods", () => {
  const dir = project("ctor", ctorFiles);
  const t = traceProject(dir);
  assert.deepEqual(t.unresolved, [], "nothing left unresolved");
  const routes = new Set(t.entryPoints.filter((e) => e.file === "routes/tickets.js").map((e) => e.route));
  assert.deepEqual([...routes].sort(), ["GET /tickets/:id", "GET /tickets/search", "POST /tickets/close"]);

  const sqlText = t.paths.filter((p) => p.sqlText);
  const search = sqlText.find((p) => p.route === "GET /tickets/search");
  assert.ok(search, "search input reaches the concatenated SQL through this.find and the DAO's member arrow");
  assert.deepEqual(search!.hops.map((h) => `${h.kind}@${h.file}:${h.line}`).filter((h) => h.startsWith("call") || h.startsWith("sink")), [
    "call@routes/tickets.js:6",
    "call@routes/tickets.js:8",
    "sink@data/ticket-dao.js:3",
  ]);
  const close = sqlText.find((p) => p.route === "POST /tickets/close");
  assert.ok(close, "a prototype method calling another through this reaches the sink");
  assert.equal(close!.hops.at(-1)!.line, 9);
  const byId = t.paths.find((p) => p.route === "GET /tickets/:id");
  assert.ok(byId && !byId.sqlText, "a bound parameter stays bound");
  assert.equal(t.coverage.registrations.filter((r) => !r.handler || r.unresolved.length > 0).length, 0, "every route and its middleware resolved");
});

test("middleware wired through a constructor function is on the route's chain and sets its identity", () => {
  const dir = project("ctor-access", ctorFiles);
  const ctx = assembleAccessContext(dir);
  const list = ctx.routes.find((r) => r.method === "GET" && r.path === "/tickets/:id");
  assert.ok(list);
  assert.deepEqual(list!.middleware.map((m) => m.name), ["this.isLoggedInMiddleware"]);
  assert.equal(list!.identity?.expression, "req.user");
  assert.ok(["id", "teamId"].every((f) => list!.identity!.fields.includes(f)), "the fields the middleware sets");
  assert.equal(list!.status, "candidate", "params.id selects a team-owned ticket, with no check against req.user.teamId");
});

test("'new' on a plain function that sets no members stays unresolved, never dropped", () => {
  const dir = project("ctor-opaque", {
    "app.js": [
      "function Store() { return makeStore(); }",
      "const store = new Store();",
      "module.exports = (router) => router.get('/s', (req, res) => store.find(req.query.q));",
      "",
    ].join("\n"),
  });
  const t = traceProject(dir);
  assert.deepEqual(t.unresolved.map((u) => u.reason), ["'new' on constructor function Store"]);
});

/** A swig project: `server.js` configures the engine; `routes/pages.js` renders `views/page.html` with request input. */
function swigProject(name: string, autoescape: string, template: string): string {
  return project(name, {
    "package.json": JSON.stringify({ dependencies: { express: "*", swig: "*", consolidate: "*" } }),
    "server.js": [
      "const express = require('express');",
      "const consolidate = require('consolidate');",
      "const swig = require('swig');",
      "const app = express();",
      "app.engine('.html', consolidate.swig);",
      "app.set('view engine', 'html');",
      "app.set('views', `${__dirname}/views`);",
      autoescape,
      "require('./routes/pages')(app);",
      "",
    ].join("\n"),
    "routes/pages.js": [
      "module.exports = (app) => {",
      "  app.get('/greet', (req, res) => {",
      "    const { name } = req.query;",
      "    const shown = { title: req.query.title };",
      "    return res.render('page', { name, ...shown, fixed: 'x' });",
      "  });",
      "};",
      "",
    ].join("\n"),
    "views/page.html": template,
  });
}

const page = "<h1>{{ title }}</h1>\n<p>Hello {{ name }}</p>\n<i>{{ fixed }}</i>\n";

test("res.render with auto-escaping off: every tainted template output is a candidate, untainted ones are not", () => {
  const t = traceXssProject(swigProject("swig-off", "swig.setDefaults({ autoescape: false });", page));
  const raw = t.xss.filter((p) => !p.encoded);
  assert.deepEqual(raw.map((p) => `${p.context} ${p.hops.at(-1)!.file}:${p.hops.at(-1)!.line}`).sort(), ["template views/page.html:1", "template views/page.html:2"]);
  const sink = raw.find((p) => p.hops.at(-1)!.line === 2)!.hops.at(-1)!;
  assert.match(sink.code, /unescaped: swig auto-escaping is off \(server\.js:8\)/);
  assert.equal(sink.fn.name, "template (swig)");
  assert.match(sink.fn.code, /Hello \{\{ name \}\}/, "the judge sees the template lines");
  const render = raw[0].hops.at(-2)!;
  assert.equal(render.file, "routes/pages.js");
  assert.match(render.code, /renders views\/page\.html with swig/);
  assert.equal(raw[0].route, "GET /greet");
});

test("res.render with auto-escaping on (the default) is encoded; |safe and {% autoescape false %} bypass it", () => {
  const safe = traceXssProject(swigProject("swig-default", "", page));
  assert.equal(safe.xss.filter((p) => !p.encoded).length, 0, "escaped by default: nothing sent to the model");
  assert.equal(safe.xss.filter((p) => p.encoded).length, 2);
  assert.match(safe.xss[0].encoder!, /swig auto-escaping is on \(the engine's default\)/);

  const bypass = traceXssProject(
    swigProject("swig-bypass", "swig.setDefaults({ autoescape: true });", "<h1>{{ title|safe }}</h1>\n{% autoescape false %}<p>{{ name }}</p>{% endautoescape %}\n<b>{{ name|escape }}</b>\n"),
  );
  const raw = bypass.xss.filter((p) => !p.encoded).map((p) => p.hops.at(-1)!);
  assert.deepEqual(raw.map((h) => h.line).sort(), [1, 2]);
  assert.match(raw.find((h) => h.line === 1)!.code, /the 'safe' filter disables swig escaping/);
  assert.match(raw.find((h) => h.line === 2)!.code, /inside \{% autoescape false %\}/);
  assert.equal(bypass.xss.find((p) => p.hops.at(-1)!.line === 3)?.encoded, true, "|escape escapes even inside the page");
});

test("res.render: EJS <%- %> is raw and <%= %> escaped; a missing template is an unresolved edge", () => {
  const ejs = project("ejs", {
    "package.json": JSON.stringify({ dependencies: { express: "*", ejs: "*" } }),
    "app.js": [
      "const app = require('express')();",
      "app.set('view engine', 'ejs');",
      "app.get('/a', (req, res) => res.render('a', { q: req.query.q }));",
      "app.get('/b', (req, res) => res.render('missing', { q: req.query.q }));",
      "",
    ].join("\n"),
    "views/a.ejs": "<p><%- q %></p>\n<p><%= q %></p>\n",
  });
  const t = traceXssProject(ejs);
  assert.deepEqual(t.xss.map((p) => [p.hops.at(-1)!.line, p.encoded]).sort(), [[1, false], [2, true]]);
  assert.deepEqual(t.unresolved.map((u) => `${u.file}:${u.line} ${u.call} — ${u.reason}`), ["app.js:4 res.render('missing') — template for view 'missing' not found"]);
});

test("res.render: handlebars {{{ }}} is raw, {{ }} escaped, and {{#each}} blocks see their list's fields", () => {
  const hbs = project("hbs", {
    "package.json": JSON.stringify({ dependencies: { express: "*", hbs: "*" } }),
    "app.js": [
      "const app = require('express')();",
      "app.set('view engine', 'hbs');",
      "app.post('/c', (req, res) => res.render('c', { items: req.body.items, note: req.body.note }));",
      "",
    ].join("\n"),
    "views/c.hbs": "{{#each items}}<li>{{{label}}}</li>{{/each}}\n<p>{{note}}</p>\n",
  });
  const t = traceXssProject(hbs);
  assert.deepEqual(t.xss.map((p) => [p.hops.at(-1)!.line, p.encoded]).sort(), [[1, false], [2, true]]);
});
