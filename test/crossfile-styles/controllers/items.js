const repo = require('../db/repo');

exports.list = async (req, res) => {
  res.json(await repo.sorted(req.query.sort));
};
