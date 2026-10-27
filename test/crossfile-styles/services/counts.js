const { count } = require('../db/repo');

exports.countItems = (term) => count(term);
