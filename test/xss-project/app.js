const express = require('express');
const catalogRoutes = require('./routes/catalog');

const app = express();

app.use('/library', catalogRoutes);

app.get('/echo', (req, res) => res.send('<p>You said: ' + req.query.msg + '</p>'));
app.get('/raw', (req, res) => res.send(req.query.text));
app.get('/count', (req, res) => res.send(`<b>${Number(req.query.n)}</b>`));
app.get('/lookup', (req, res) => res.send({ q: req.query.q }));

module.exports = app;
