const express = require("express");
const products = require("./routes/products");
const search = require("./routes/search");

const app = express();
app.use(products);
app.use(search);

app.get("/health", (req, res) => res.send("ok"));

app.listen(process.env.PORT || 3000);
