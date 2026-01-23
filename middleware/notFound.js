// middleware/notFound.js
function notFound(req, res, next) {
  res.status(404).json({ ok: false, error: "Not Found", path: req.originalUrl });
}

module.exports = { notFound };
