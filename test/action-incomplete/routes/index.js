const handlers = ["session", "contributions", "allocations"];
const load = (name) => require("./" + name);

module.exports = (app) => {
  const [session, contributions, allocations] = handlers.map(load);
  const isLoggedIn = session.isLoggedInMiddleware;

  app.get("/login", session.displayLoginPage);
  app.post("/contributions", isLoggedIn, contributions.handleContributionsUpdate);
  app.get("/allocations/:userId", isLoggedIn, allocations.displayAllocations);
  app.get("/health", (req, res) => res.send("ok"));
};
