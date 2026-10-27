const repo = require('../db/repo');

function findItems(name) {
  return repo.byName(name);
}

module.exports = { findItems };
