import db from '../../db';

export default async function handler(req, res) {
  const { id } = req.query;
  res.json(await db.run('SELECT id, name FROM users WHERE id = $1', [id]));
}
