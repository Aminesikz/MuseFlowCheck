const express = require('express');
const orderService = require('../services/orderService');

const router = express.Router();

router.get('/search', async (req, res) => {
  const term = req.query.q;
  res.json(await orderService.searchOrders(term));
});

router.get('/:id', async (req, res) => {
  res.json(await orderService.getOrder(req.params.id));
});

module.exports = router;
