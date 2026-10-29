const store = require('../db/store');
const { results } = require('../templates/results');

async function findPage(title, author) {
  const books = (await store.lookup(title)).filter((b) => b.visible);
  const heading = title.trim();
  return results({ title: heading, author, books });
}

module.exports = { findPage };
