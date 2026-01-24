// routes/auth.js
const express = require("express");
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
    const { email, password } = signupSchema.parse(req.body);

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const userRes = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email, email_verified_at, created_at`,
      [email, passwordHash]
    );

    const user = userRes.rows[0];

    const { sessionId, expiresAt } = await createSession(user.id);

    const cookieName = process.env.SESSION_COOKIE_NAME || "sid";
    res.cookie(cookieName, sessionId, {
      ...getCookieOptions(),
      expires: new Date(expiresAt),
    });

    res.status(201).json({
      ok: true,
      user: { id: user.id, email: user.email, emailVerifiedAt: user.email_verified_at },
      session: { expiresAt },
    });
  } catch (err) {
    // Handle duplicate email nicely
    if (err && err.code === "23505") {
      return res.status(409).json({ ok: false, message: "Email already in use" });
    }
    next(err);
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
    const sid = req.cookies?.[cookieName];

    if (sid) await deleteSession(sid);

    res.clearCookie(cookieName, { ...getCookieOptions() });
    res.status(200).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Test endpoint: confirms auth + triggers sliding expiration
router.get("/me", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(
      `SELECT id, email, email_verified_at, created_at
       FROM users
       WHERE id = $1`,
      [req.auth.userId]
    );

    const user = r.rows[0];
    res.json({
      ok: true,
      user,
      session: { expiresAt: req.auth.expiresAt },
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
