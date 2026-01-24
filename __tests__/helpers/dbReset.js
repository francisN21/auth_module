const { pool } = require("../../src/db");

async function resetDb() {
  await pool.query(
    "TRUNCATE TABLE email_tokens, sessions, oauth_identities, users RESTART IDENTITY CASCADE"
  );
}

module.exports = { resetDb };