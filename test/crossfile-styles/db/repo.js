const { pool } = require('./client');

module.exports = {
  async byName(name, limit = 50) {
    return pool.query(`SELECT id FROM items WHERE name = '${name}' LIMIT ${limit}`);
  },
  count(term) {
    return pool.query('SELECT COUNT(*) FROM items WHERE name LIKE $1', [`%${term}%`]);
  },
  sorted: function (column) {
    return pool.query('SELECT id FROM items ORDER BY ' + column);
  },
};
