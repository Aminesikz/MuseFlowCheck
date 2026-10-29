const db = require('../db');

exports.byRegion = async (region, tags) => {
  const wanted = tags.filter((t) => t.length > 0);
  const sql = "SELECT * FROM sales WHERE region = '" + region + "'";
  return db.query(sql, wanted);
};
