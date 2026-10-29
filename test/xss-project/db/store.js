const { Pool } = require('pg');

const pool = new Pool();

exports.lookup = async (title) => {
  const { rows } = await pool.query('SELECT name, visible FROM books WHERE title ILIKE $1', [title]);
  return rows;
};
