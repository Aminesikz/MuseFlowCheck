const express = require('express');

const router = express.Router();

// Two request inputs into the same HTML output.
router.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.first + ' ' + req.query.last + '</h1>');
});

// One request input into an HTML output.
router.get('/bye', (req, res) => {
  res.send('<p>Goodbye ' + req.query.name + '</p>');
});

module.exports = router;
