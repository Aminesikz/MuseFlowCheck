const db = require("../../db");

exports.byUser = (userId, threshold, cb) =>
  db.query("SELECT * FROM allocations WHERE user_id = " + userId + " AND stocks > " + threshold, cb);
