const express = require("express");
const db = require("../db");

const router = express.Router();

router.get("/products", async (req, res) => {
  const { rows } = await db.query("SELECT id, name, price FROM products WHERE category = $1", [req.query.category]);
  res.json(rows);
});

module.exports = router;
