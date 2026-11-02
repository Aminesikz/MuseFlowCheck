const dao = require(process.env.CONTRIBUTIONS_DAO || "../app/data/contributions-dao");

exports.handleContributionsUpdate = (req, res) => {
  dao.update(req.session.userId, req.body.preTax, req.body.afterTax, (err) => {
    if (err) return res.status(500).send(err.message);
    res.redirect("/contributions");
  });
};
