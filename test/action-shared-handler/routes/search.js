const express = require("express");
const db = require("../db");

const router = express.Router();

// Product search page.
router.get("/search", async (req, res) => {
  const q = req.query.q;
  const { rows } = await db.query("SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'");
  const items = rows.map((r) => `<li>${r.name} — $${r.price}</li>`).join("");
  res.send(`<h1>Results for ${q}</h1><ul>${items}</ul>`);
});

module.exports = router;
