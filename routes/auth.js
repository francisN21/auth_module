// routes/auth.js
const express = require("express");
const router = express.Router();

// Placeholder: email/password signup
router.post("/signup", (req, res) => {
  res.status(501).json({ ok: false, message: "Not implemented: /auth/signup" });
});

// Placeholder: email/password login
router.post("/login", (req, res) => {
  res.status(501).json({ ok: false, message: "Not implemented: /auth/login" });
});

// Placeholder: logout (session cookie clearing later)
router.post("/logout", (req, res) => {
  res.status(200).json({ ok: true, message: "Logged out (placeholder)" });
});

module.exports = router;
