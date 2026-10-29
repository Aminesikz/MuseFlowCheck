const express = require('express');
const service = require('../services/posts');

const router = express.Router();

router.post('/posts', async (req, res) => {
  const post = await service.publish(req.body.title, req.body.body);
  res.status(201).json({ post });
});

router.get('/posts/:id', async (req, res) => {
  res.json({ post: await service.find(req.params.id) });
});

router.get('/posts/:id/page', async (req, res) => {
  res.type('html').send(await service.page(req.params.id));
});

module.exports = router;
