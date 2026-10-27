class Reporter {
  constructor(repo) {
    this.repo = repo;
  }

  run(column) {
    return this.repo.sorted(column);
  }
}

module.exports = new Reporter(require('../db/repo'));
