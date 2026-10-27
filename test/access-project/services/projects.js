const projects = require('../db/projects');

async function load(id) {
  const { rows } = await projects.byId(id);
  return rows[0];
}

async function loadOwned(id, teamId) {
  const project = await load(id);
  if (!project || project.team_id !== teamId) {
    throw Object.assign(new Error('not found'), { status: 404 });
  }
  return project;
}

module.exports = { load, loadOwned };
