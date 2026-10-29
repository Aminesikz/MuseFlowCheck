const express = require('express');
const store = require('../db/workspace');
const { page } = require('../views/workspace');

const router = express.Router();

router.post('/drafts', async (req, res) => {
  await store.saveDraft(req.user.id, req.body.text);
  res.status(204).end();
});

router.get('/drafts/:id/page', async (req, res) => {
  const draft = await store.draft(req.params.id);
  if (!draft || draft.owner_id !== req.user.id) return res.status(404).end();
  res.type('html').send(page(draft.text));
});

router.post('/notices', async (req, res) => {
  await store.saveNotice(req.body.message);
  res.status(204).end();
});

router.get('/notices/latest/page', async (req, res) => {
  if (!req.user) return res.status(401).end();
  const notice = await store.latestNotice();
  res.type('html').send(page(notice.message));
});

module.exports = router;
