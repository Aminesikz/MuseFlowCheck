const { pool } = require('../db/client');

function createAudit(db) {
  return {
    record(entry) {
      return db.query("INSERT INTO audit (entry) VALUES ('" + entry + "')");
    },
  };
}

module.exports = createAudit(pool);
