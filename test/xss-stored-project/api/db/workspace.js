const { Pool } = require('pg');

const pool = new Pool();

exports.saveDraft = (owner, text) => pool.query('INSERT INTO drafts (owner_id, text) VALUES ($1, $2)', [owner, text]);

exports.draft = async (id) => (await pool.query('SELECT id, owner_id, text FROM drafts WHERE id = $1', [id])).rows[0];

exports.saveNotice = (message) => pool.query('INSERT INTO notices (message) VALUES ($1)', [message]);

exports.latestNotice = async () => (await pool.query('SELECT message FROM notices ORDER BY id DESC LIMIT 1')).rows[0];
