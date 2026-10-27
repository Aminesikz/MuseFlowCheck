const express = require('express');
const { findItems } = require('../services');
const svc = require('../services');
const catalog = require('../services/catalog');
const controller = require('../controllers/items');
const plugin = require(process.env.ITEMS_PLUGIN);
const audit = require('../services/audit');
const reporter = require('../services/reporter');
const inventory = require('../services/inventory');
const Search = require('../services/search');
const orders = require('../controllers/orders');

const router = express.Router();

router.get('/a', async (req, res) => {
  res.json(await findItems(req.query.a));
});

router.get('/b', async (req, res) => {
  const term = req.query.b;
  res.json(await svc.countItems(term));
});

router.get('/c', async (req, res) => {
  res.json(await catalog.lookup({ name: req.query.c, limit: 10 }));
});

router.get('/d', async (req, res) => {
  res.json(await plugin.run(req.query.d));
});

router.get('/e', async (req, res) => {
  res.json(await svc.removed(req.query.e));
});

router.get('/f', controller.list);

router.post('/g', async (req, res) => {
  await audit.record(req.body.note);
  res.sendStatus(204);
});

router.get('/h', async (req, res) => {
  res.json(await reporter.run(req.query.by));
});

router.get('/i', async (req, res) => {
  res.json(await inventory.sortedBy(req.query.col));
});

router.get('/j', async (req, res) => {
  res.json(await new Search(req.query.j).run());
});

router.get('/k', orders.list);

module.exports = router;
