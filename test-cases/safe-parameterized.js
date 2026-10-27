const express = require('express');
const Database = require('better-sqlite3');

const store = new Database('orders.db');
const router = express.Router();
const SORTABLE = ['placed_at', 'total'];

router.get('/orders', (req, res) => {
  const customer = req.query.customer;
  const sort = SORTABLE.includes(req.query.sort) ? req.query.sort : 'placed_at';
  const limit = Number.parseInt(req.query.limit, 10) || 20;
  const rows = store
    .prepare(`SELECT id, total FROM orders WHERE customer_id = ? ORDER BY ${sort} LIMIT ${limit}`)
    .all(customer);
  res.json(rows);
});

module.exports = router;
