// middleware/requireAuth.js
const { getSession, touchSession } = require("../src/auth/session");

async function requireAuth(req, res, next) {
  try {
    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    const sid = req.cookies?.[cookieName];

    if (!sid) {
      return res.status(401).json({ ok: false, message: "Not authenticated" });
    }

    const session = await getSession(sid);
    if (!session) {
      return res.status(401).json({ ok: false, message: "Invalid session" });
    }

    // Expired?
    if (new Date(session.expires_at).getTime() <= Date.now()) {
      return res.status(401).json({ ok: false, message: "Session expired" });
    }

    // Sliding refresh
    const updated = await touchSession(sid);

    req.auth = {
      userId: updated.user_id,
      sessionId: updated.id,
      expiresAt: updated.expires_at,
    };

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { requireAuth };