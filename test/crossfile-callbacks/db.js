const { Pool } = require('pg');

const pool = new Pool();

exports.query = (sql, params) => pool.query(sql, params);
