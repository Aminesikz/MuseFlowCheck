CREATE TABLE teams (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE projects (
  id SERIAL PRIMARY KEY,
  team_id INTEGER NOT NULL REFERENCES teams(id),
  title TEXT NOT NULL
);

CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  project_id INTEGER NOT NULL,
  team_id INTEGER NOT NULL,
  body TEXT,
  CONSTRAINT documents_team FOREIGN KEY (team_id) REFERENCES teams (id)
);

CREATE TABLE tags (
  id SERIAL PRIMARY KEY,
  label TEXT NOT NULL
);
