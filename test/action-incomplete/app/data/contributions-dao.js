const db = require("../../db");

exports.update = (userId, preTax, afterTax, cb) =>
  db.query("UPDATE contributions SET pre_tax = " + preTax + ", after_tax = " + afterTax + " WHERE user_id = $1", [userId], cb);
