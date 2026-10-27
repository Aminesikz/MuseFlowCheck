const express = require('express');
const projects = require('../db/projects');

const router = express.Router();

router.get('/:projectId', async (req, res) => {
  res.json(await projects.byId(req.params.projectId));
});

module.exports = router;
