const BaseService = require('./base');
const repo = require('../db/repo');

class Inventory extends BaseService {
  constructor() {
    super(repo);
  }
}

module.exports = new Inventory();
