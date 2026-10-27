const repo = require('../db/repo');

class OrdersController {
  constructor(store) {
    this.store = store;
  }

  list = async (req, res) => {
    res.json(await this.store.sorted(req.query.order));
  };
}

module.exports = new OrdersController(repo);
