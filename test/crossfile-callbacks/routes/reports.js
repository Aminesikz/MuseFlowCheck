const reports = require('../services/reports');

exports.summary = async (req, res) => {
  const tags = (req.query.tags || '').split(',').map((t) => t.trim());
  const rows = await reports.byRegion(req.query.region, tags);
  res.json(rows);
};
