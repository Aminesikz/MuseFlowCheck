class ReportsController {
  constructor(db) {
    this.db = db;
  }

  async show(req, res) {
    res.json(await this.db.run(`SELECT * FROM reports WHERE kind = '${req.params.kind}'`));
  }
}

module.exports = ReportsController;
