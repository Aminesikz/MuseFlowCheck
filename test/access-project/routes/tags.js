const express = require('express');
const projects = require('../db/projects');

const router = express.Router();

router.get('/:tagId', async (req, res) => {
  res.json(await projects.tag(req.params.tagId));
});

module.exports = router;
