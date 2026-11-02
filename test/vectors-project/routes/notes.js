const express = require('express');
const notes = require('../db/notes');

const router = express.Router();

router.get('/', async (req, res) => {
  const { teamId, status } = req.query;
  res.json(await notes.list(teamId || req.user.teamId, status));
});

router.get('/search', async (req, res) => {
  res.json(await notes.search(req.query.q));
});

router.get('/:id', async (req, res) => {
  res.json(await notes.byId(req.params.id));
});

// Two request identifiers, each selecting a notes row with no team check.
router.get('/:id/compare', async (req, res) => {
  const left = await notes.byId(req.params.id);
  const right = await notes.byId(req.query.otherId);
  res.json({ left, right });
});

// Two identifiers into different tables: separate accesses, not vectors of one.
router.get('/:id/with-team', async (req, res) => {
  const note = await notes.byId(req.params.id);
  const team = await notes.team(req.query.teamId);
  res.json({ note, team });
});

module.exports = router;
