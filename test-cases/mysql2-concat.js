const express = require('express');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({ host: 'localhost', user: 'app', database: 'shop' });
const router = express.Router();

router.get('/members', async (req, res) => {
  const email = req.query.email;
  const query = "SELECT id, email, plan FROM members WHERE email = '" + email + "'";
  const [rows] = await pool.execute(query);
  res.json(rows);
});

module.exports = router;
