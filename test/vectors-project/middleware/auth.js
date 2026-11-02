function authenticate(req, res, next) {
  const claims = JSON.parse(Buffer.from(req.headers.authorization || '', 'base64').toString('utf8'));
  if (!claims.sub) return res.status(401).end();
  req.user = { id: claims.sub, teamId: claims.team };
  next();
}

module.exports = { authenticate };
