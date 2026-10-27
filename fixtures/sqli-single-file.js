const express = require('express');
const { Pool } = require('pg');

const pool = new Pool();
const router = express.Router();

router.get('/users/search', async (req, res) => {
  const name = req.query.name;
  const sql = "SELECT id, email FROM users WHERE name = '" + name + "'";
  const { rows } = await pool.query(sql);
  res.json(rows);
});

router.get('/users/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.params.id]);
  res.json(rows[0] || null);
});

module.exports = router;
