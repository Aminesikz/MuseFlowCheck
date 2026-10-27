const express = require('express');
const mysql = require('mysql2/promise');

const app = express();
app.use(express.json());
const conn = mysql.createPool({ host: 'localhost', user: 'app', database: 'inventory' });

function whereClause(column, value) {
  return 'WHERE '.concat(column, " = '", value, "'");
}

app.post('/inventory/lookup', async (req, res) => {
  let { warehouse } = req.body;
  const region = warehouse;
  const statement = 'SELECT sku, qty FROM stock '.concat(whereClause('warehouse_code', region));
  const [rows] = await conn.query(statement);
  res.json(rows);
});

module.exports = app;
