const express = require('express');
const sql = require('mssql');

const router = express.Router();
const connected = sql.connect(process.env.MSSQL_URL);

router.get('/invoices/:invoiceId', async (req, res) => {
  const pool = await connected;
  const q = pool.request();
  const found = await q.query('SELECT id, amount, status FROM invoices WHERE id = ' + req.params.invoiceId);
  res.json(found.recordset);
});

module.exports = router;
