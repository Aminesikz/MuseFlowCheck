const db = require('../db/posts');
const { renderPost } = require('../views/post');

async function publish(title, body) {
  return db.insert(title.trim(), body);
}

async function find(id) {
  return db.byId(Number(id));
}

async function page(id) {
  const post = await db.byId(Number(id));
  return renderPost(post);
}

module.exports = { publish, find, page };
