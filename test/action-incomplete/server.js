// NodeGoat-style app the tracer cannot follow: handlers and data access are loaded through computed module paths.
const express = require("express");
const routes = require("./routes");

const app = express();
app.use(express.urlencoded({ extended: false }));
routes(app);
app.listen(process.env.PORT || 4000);
