const repo = require('../db/repo');

class Catalog {
  async lookup({ name, limit }) {
    return this.search(name, limit);
  }

  async search(name, limit) {
    return repo.byName(name, limit);
  }
}

module.exports = new Catalog();
