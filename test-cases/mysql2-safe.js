const express = require('express');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({ host: 'localhost', user: 'app', database: 'shop' });
const router = express.Router();

router.get('/accounts/:accountId', async (req, res) => {
  const [rows] = await pool.execute('SELECT id, email, plan FROM accounts WHERE id = ? AND plan = ?', [req.params.accountId, req.query.plan || 'free']);
  res.json(rows[0] || null);
});

router.post('/accounts', async (req, res) => {
  const { email, plan } = req.body;
  await pool.query('INSERT INTO accounts (email, plan) VALUES (?, ?)', [email, plan]);
  res.status(201).end();
});

module.exports = router;
