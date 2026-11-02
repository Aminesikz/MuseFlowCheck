const express = require('express');
const { authenticate } = require('./middleware/auth');
const noteRoutes = require('./routes/notes');
const pageRoutes = require('./routes/pages');

const app = express();
app.use(express.json());
app.use('/notes', authenticate, noteRoutes);
app.use('/pages', pageRoutes);

module.exports = app;
