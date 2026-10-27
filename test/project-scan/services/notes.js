exports.add = (text) => require('../db').run('INSERT INTO notes (text) VALUES ($1)', [text]);
