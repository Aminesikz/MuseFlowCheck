const { search, byId: fetchById } = require('../db/orders');

const searchOrders = async (text) => {
  const needle = text.toLowerCase();
  return search(needle);
};

async function getOrder(id) {
  return fetchById(id);
}

module.exports = { searchOrders, getOrder };
