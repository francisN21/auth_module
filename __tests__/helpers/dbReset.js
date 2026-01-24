const { pool } = require("../../src/db");

async function resetDb() {
  // Order matters because of FK constraints
  await pool.query("TRUNCATE TABLE email_tokens RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE TABLE sessions RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE TABLE oauth_identities RESTART IDENTITY CASCADE");
  await pool.query("TRUNCATE TABLE users RESTART IDENTITY CASCADE");
}

module.exports = { resetDb };
