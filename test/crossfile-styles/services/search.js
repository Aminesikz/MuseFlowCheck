const { pool } = require('../db/client');

class Search {
  constructor(text) {
    this.text = text;
  }

  run() {
    return pool.query("SELECT id FROM items WHERE name = '" + this.text + "'");
  }
}

module.exports = Search;
