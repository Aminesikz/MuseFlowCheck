function decode(header) {
  const claims = JSON.parse(Buffer.from(header || '', 'base64').toString('utf8'));
  return { id: claims.sub, teamId: claims.team };
}

function authenticate(req, res, next) {
  const member = decode(req.headers.authorization);
  if (!member.id) return res.status(401).end();
  req.user = member;
  next();
}

function sameTeam(req, res, next) {
  if (Number(req.params.teamId) !== req.user.teamId) return res.status(403).end();
  next();
}

module.exports = { authenticate, sameTeam };
