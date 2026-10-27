const express = require('express');
const { authenticate } = require('./middleware/auth');
const projectRoutes = require('./routes/projects');
const teamRoutes = require('./routes/teams');
const tagRoutes = require('./routes/tags');
const shareRoutes = require('./routes/share');

const app = express();
app.use(express.json());
app.use('/share', shareRoutes);
app.use('/projects', authenticate, projectRoutes);
app.use('/teams', authenticate, teamRoutes);
app.use('/tags', authenticate, tagRoutes);

module.exports = app;
