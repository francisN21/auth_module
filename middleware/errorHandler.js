// middleware/errorHandler.js
function errorHandler(err, req, res, next) {
  const status = Number(err.status || 500);
  const isProd = process.env.NODE_ENV === "production";

  res.status(status).json({
    ok: false,
    error: err.name || "Error",
    message: err.message || "Something went wrong",
    ...(isProd ? {} : { stack: err.stack }),
  });
}

module.exports = { errorHandler };
