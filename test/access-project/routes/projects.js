const express = require('express');
const service = require('../services/projects');
const projects = require('../db/projects');

const router = express.Router();

router.get('/:projectId', async (req, res) => {
  res.json(await service.load(req.params.projectId));
});

router.get('/:projectId/owned', async (req, res) => {
  res.json(await service.loadOwned(req.params.projectId, req.user.teamId));
});

router.get('/:projectId/checked', async (req, res) => {
  const project = await service.load(req.params.projectId);
  if (!project || project.team_id !== req.user.teamId) return res.status(404).end();
  res.json(project);
});

router.get('/:projectId/scoped', async (req, res) => {
  res.json(await projects.byIdForTeam(req.params.projectId, req.user.teamId));
});

router.delete('/:projectId', async (req, res) => {
  await projects.remove(req.params.projectId);
  res.status(204).end();
});

router.put('/:projectId', async (req, res) => {
  const { rows } = await projects.rename(req.params.projectId, req.body.title);
  if (rows[0].team_id !== req.user.teamId) return res.status(403).end();
  res.json(rows[0]);
});

module.exports = router;
