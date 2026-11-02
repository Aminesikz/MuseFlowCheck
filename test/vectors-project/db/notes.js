const db = require('./client');

// Two request inputs concatenated into one statement.
async function list(teamId, status) {
  let sql = 'SELECT id, team_id, title, status FROM notes WHERE team_id = ' + teamId;
  if (status) {
    sql += " AND status = '" + status + "'";
  }
  const { rows } = await db.query(sql);
  return rows;
}

// One request input concatenated into the statement.
async function search(term) {
  const { rows } = await db.query("SELECT id, title FROM notes WHERE title LIKE '%" + term + "%'");
  return rows;
}

async function byId(id) {
  const { rows } = await db.query('SELECT id, team_id, title, status FROM notes WHERE id = $1', [id]);
  return rows[0];
}

async function team(id) {
  const { rows } = await db.query('SELECT id, name FROM teams WHERE id = $1', [id]);
  return rows[0];
}

module.exports = { list, search, byId, team };
