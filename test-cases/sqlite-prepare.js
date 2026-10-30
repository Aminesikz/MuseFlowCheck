const express = require('express');
const Database = require('better-sqlite3');

const db = new Database('library.db');
const app = express();

app.get('/books', (req, res) => {
  const author = (req.query.author || '').trim();
  const books = db.prepare("SELECT title, year FROM books WHERE author LIKE '%" + author + "%' ORDER BY year").all();
  res.json(books);
});

module.exports = app;
