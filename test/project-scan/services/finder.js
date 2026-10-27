const db = require('../db');

exports.find = async (request) => {
  const name = request.query.name;
  return db.run("SELECT id FROM people WHERE name = '" + name + "'");
};
