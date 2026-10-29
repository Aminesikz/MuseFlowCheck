const escape = require('escape-html');

function renderPost(post) {
  return `<article>
  <h1>${escape(post.title)}</h1>
  <p class="by">${post.author}</p>
  <div class="body">${post.body}</div>
</article>`;
}

module.exports = { renderPost };
