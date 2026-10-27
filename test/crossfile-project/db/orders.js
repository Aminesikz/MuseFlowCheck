const { client } = require('./client');

exports.search = async function (needle) {
  const sql = `SELECT id FROM orders WHERE note LIKE '%${needle}%'`;
  return client.query(sql);
};

exports.byId = async function (id) {
  return client.query('SELECT id FROM orders WHERE id = $1', [id]);
};
