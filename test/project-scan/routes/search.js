const finder = require('../services/finder');

exports.byName = async (req, res) => {
  res.json(await finder.find(req));
};
