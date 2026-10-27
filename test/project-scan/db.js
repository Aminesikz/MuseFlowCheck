const { Pool } = require('pg');

const pool = new Pool();

module.exports = {
  run: (sql, params) => pool.query(sql, params),
};
