exports.isLoggedInMiddleware = (req, res, next) => (req.session.userId ? next() : res.redirect("/login"));
exports.displayLoginPage = (req, res) => res.render("login", { userName: "", password: "" });
