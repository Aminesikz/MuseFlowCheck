const express = require('express');
const posts = require('./routes/posts');

const app = express();
app.use(express.json());
app.use('/forum', posts);

module.exports = app;
