const he = require('he');
const { encode, escapeText } = require('./encode');

function summary(title) {
  return 'Books matching "' + title + '"';
}

function results({ title, author, books }) {
  return `<section>
  <h2>${summary(title)}</h2>
  <input name="title" value="${encode(title)}">
  <p class="by">${he.encode(author)}</p>
  <p class="hint">${escapeText(author)}</p>
  <ul>${books.map((b) => `<li>${encode(b.name)}</li>`).join('')}</ul>
</section>`;
}

module.exports = { results };
