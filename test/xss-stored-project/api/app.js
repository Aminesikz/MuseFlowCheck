const express = require('express');
const posts = require('./routes/posts');
const workspace = require('./routes/workspace');

const app = express();
app.use(express.json());
app.use('/forum', posts);
app.use('/workspace', workspace);

module.exports = app;
