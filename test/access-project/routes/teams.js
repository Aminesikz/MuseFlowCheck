const express = require('express');
const { sameTeam } = require('../middleware/auth');
const projects = require('../db/projects');

const router = express.Router();

router.get('/:teamId/totals', sameTeam, async (req, res) => {
  res.json(await projects.totals(req.params.teamId));
});

router.get('/:teamId/report', async (req, res) => {
  res.json(await projects.totals(req.params.teamId));
});

module.exports = router;
