// routes/auth.js
const express = require("express");
const crypto = require("crypto");
const argon2 = require("argon2");
const { z } = require("zod");

const { pool } = require("../src/db");
const {
  getCookieOptions,
  createSession,
  deleteSession,
} = require("../src/auth/session");
const { requireAuth } = require("../middleware/requireAuth");

const router = express.Router();

function addHours(date, hours) {
  return new Date(date.getTime() + hours * 60 * 60 * 1000);
}

function setSessionCookie(res, sid, expiresAt) {
  res.cookie("sid", sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // set true in prod with HTTPS
    expires: expiresAt,
    path: "/",
  });
}

const signupSchema = z.object({
  email: z.string().email().transform((s) => s.trim()),
  password: z.string().min(8).max(128),
});

const loginSchema = z.object({
  email: z.string().email().transform((s) => s.trim()),
  password: z.string().min(1).max(128),
});

router.post("/signup", async (req, res, next) => {
  try {
    const { fullName, email, phone, password, accountType, address } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ ok: false, message: "Missing required fields" });
    }

    const existing = await pool.query(`SELECT id FROM users WHERE email = $1`, [email.toLowerCase()]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ ok: false, message: "Email already in use" });
    }

    const passwordHash = await argon2.hash(password);

    const created = await pool.query(
      `
      INSERT INTO users (email, password_hash, full_name, phone, account_type, address)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, email, full_name, email_verified_at, created_at
      `,
      [
        email.toLowerCase(),
        passwordHash,
        fullName,
        phone || null,
        accountType || null,
        address || null,
      ]
    );

    const user = created.rows[0];

    // Create session row
    const { sessionId, expiresAt } = await createSession(user.id);

    // Set cookie (use same cookieName everywhere)
    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    res.cookie(cookieName, sessionId, {
      ...getCookieOptions(),
      expires: new Date(expiresAt),
    });

    return res.status(201).json({
      ok: true,
      user,
      session: { expiresAt },
    });
  } catch (e) {
    next(e);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const r = await pool.query(
      `SELECT id, email, password_hash, email_verified_at
       FROM users
       WHERE email = $1`,
      [email]
    );

    const user = r.rows[0];
    if (!user || !user.password_hash) {
      return res.status(401).json({ ok: false, message: "Invalid email or password" });
    }

    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ ok: false, message: "Invalid email or password" });
    }

    const { sessionId, expiresAt } = await createSession(user.id);

    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    res.cookie(cookieName, sessionId, {
      ...getCookieOptions(),
      expires: new Date(expiresAt),
    });

    res.status(200).json({
      ok: true,
      user: { id: user.id, email: user.email, emailVerifiedAt: user.email_verified_at },
      session: { expiresAt },
    });
  } catch (err) {
    next(err);
  }
});

router.post("/logout", async (req, res, next) => {
  try {
    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    const sessionId = req.cookies?.[cookieName];

    if (sessionId) await deleteSession(sessionId);

    res.clearCookie(cookieName, { ...getCookieOptions() });
    res.status(200).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Test endpoint: confirms auth + triggers sliding expiration
router.get("/me", async (req, res, next) => {
  try {
    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    const sessionId = req.cookies?.[cookieName];

    if (!sessionId) {
      return res.status(401).json({ ok: false, message: "Not authenticated" });
    }

    const s = await pool.query(
      `SELECT id, user_id, expires_at, last_seen_at
       FROM sessions
       WHERE id = $1`,
      [sessionId]
    );

    if (s.rowCount === 0) {
      return res.status(401).json({ ok: false, message: "Not authenticated" });
    }

    const session = s.rows[0];
    const now = new Date();

    if (new Date(session.expires_at) <= now) {
      return res.status(401).json({ ok: false, message: "Not authenticated" });
    }

    const u = await pool.query(
      `SELECT id, email, full_name, phone, account_type, address, email_verified_at, created_at
       FROM users
       WHERE id = $1`,
      [session.user_id]
    );

    if (u.rowCount === 0) {
      return res.status(401).json({ ok: false, message: "Not authenticated" });
    }

    // Sliding expiration: extend 24h from now
    const newExpiresAt = addHours(now, 24);

    await pool.query(
      `UPDATE sessions
       SET expires_at = $1, last_seen_at = now()
       WHERE id = $2`,
      [newExpiresAt, sessionId]
    );

    // Refresh cookie expiry too
    res.cookie(cookieName, sessionId, {
      ...getCookieOptions(),
      expires: newExpiresAt,
    });

    return res.json({
      ok: true,
      user: u.rows[0],
      session: { expiresAt: newExpiresAt.toISOString() },
    });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
