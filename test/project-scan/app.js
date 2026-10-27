const express = require('express');
const Router = require('@koa/router');
const asyncHandler = require('express-async-handler');
const search = require('./routes/search');
const ReportsController = require('./controllers/reports');
const cache = require('./lib/cache');

const app = express();
const reports = new ReportsController(require('./db'));

app.get('/search', search.byName);
app.get('/search/legacy', search.byName);
app.get('/reports/:kind', asyncHandler(reports.show.bind(reports)));
cache.get('warm', (key) => key.length);

const koa = new Router();
koa.post('/notes', async (ctx) => {
  ctx.body = await require('./services/notes').add(ctx.request.body.text);
});

module.exports = { app, koa };
