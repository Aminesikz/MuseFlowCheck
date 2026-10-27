const db = require('./client');

exports.byId = (id) => db.query('SELECT id, team_id, title FROM projects WHERE id = $1', [id]);

exports.byIdForTeam = (id, teamId) =>
  db.query('SELECT id, team_id, title FROM projects WHERE id = $1 AND team_id = $2', [id, teamId]);

exports.remove = (id) => db.query('DELETE FROM projects WHERE id = $1', [id]);

exports.rename = (id, title) => db.query('UPDATE projects SET title = $1 WHERE id = $2 RETURNING team_id', [title, id]);

exports.totals = (teamId) => db.query('SELECT COUNT(*) FROM documents WHERE team_id = $1', [teamId]);

exports.tag = (tagId) => db.query('SELECT id, label FROM tags WHERE id = $1', [tagId]);
