const { Pool } = require('pg');

const pool = new Pool();

const SELECT_POST = 'SELECT id, title, body, author FROM posts WHERE id = $1';

exports.insert = async (title, body) => {
  const { rows } = await pool.query('INSERT INTO posts (title, body) VALUES ($1, $2) RETURNING id', [title, body]);
  return rows[0];
};

exports.byId = async (id) => {
  const { rows } = await pool.query(SELECT_POST, [id]);
  return rows[0];
};
