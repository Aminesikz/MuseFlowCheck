exports.encode = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

exports.escapeText = function (s) {
  return s.trim().replace(/\s+/g, ' ');
};
