const express = require('express');
const catalog = require('../services/catalog');

const router = express.Router();

router.get('/find', async (req, res) => {
  const page = await catalog.findPage(req.query.title, req.query.author);
  res.type('html').send(page);
});

module.exports = router;
