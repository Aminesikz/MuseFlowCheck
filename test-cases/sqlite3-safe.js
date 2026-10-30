const express = require('express');
const sqlite3 = require('sqlite3');

const db = new sqlite3.Database('notes.db');
const app = express();

app.get('/notes', (req, res) => {
  db.all('SELECT id, body FROM notes WHERE folder = ? ORDER BY id DESC', [req.query.folder], (err, notes) => {
    if (err) return res.status(500).end();
    res.json(notes);
  });
});

app.get('/notes/:noteId', (req, res) => {
  const cache = new Map();
  const hit = cache.get(req.params.noteId);
  if (hit) return res.json(hit);
  db.get('SELECT id, body FROM notes WHERE id = $id', { $id: req.params.noteId }, (err, note) => res.json(note));
});

module.exports = app;
