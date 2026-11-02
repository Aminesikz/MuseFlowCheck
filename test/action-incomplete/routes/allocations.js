const dao = require(process.env.ALLOCATIONS_DAO || "../app/data/allocations-dao");

exports.displayAllocations = (req, res) => {
  dao.byUser(req.params.userId, req.query.threshold, (err, rows) => res.json(rows));
};
