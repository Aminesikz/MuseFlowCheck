class BaseService {
  constructor(repo) {
    this.repo = repo;
  }

  sortedBy(column) {
    return this.repo.sorted(column);
  }
}

module.exports = BaseService;
