const express = require('express');
const sql = require('mssql');

const router = express.Router();
const connected = sql.connect(process.env.MSSQL_URL);

router.get('/receipts/:receiptId', async (req, res) => {
  const pool = await connected;
  const found = await pool
    .request()
    .input('receiptId', sql.Int, req.params.receiptId)
    .input('state', sql.NVarChar, req.query.state || 'open')
    .query('SELECT id, amount FROM receipts WHERE id = @receiptId AND state = @state');
  res.json(found.recordset);
});

module.exports = router;
