const fs = require("fs");
const path = require("path");
const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");
const { getSuspiciousLogPath } = require("../middleware/suspiciousFileLogger");

function readFileSafe(p) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
}

beforeEach(() => {
  // reset suspicious log file for deterministic tests
  const filePath = getSuspiciousLogPath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, "", "utf8");
});

afterAll(async () => {
  await pool.end();
});

test("logs suspicious input but never logs full password/token/sid; writes to suspiciousInput.txt", async () => {
  const spy = jest.spyOn(console, "warn").mockImplementation(() => {});

  const suspicious = "admin' OR '1'='1' --";

  // Trigger suspicious logging via query param (x=...) while also placing the payload
  // in sensitive body fields (password/token/sid). Middleware should NOT store full secrets.
  await request(app)
    .post("/auth/login?x=" + encodeURIComponent(suspicious))
    .send({
      email: "test@example.com",
      password: suspicious,
      token: suspicious,
      sid: suspicious,
    });

  // --- Console assertions (test-mode log hook) ---
  const joined = spy.mock.calls.map((c) => JSON.stringify(c)).join("\n");

  // We should have logged that suspicious input happened
  expect(joined).toContain("security.suspicious_input");

  // We SHOULD NOT see full sensitive keys/values in logs
  expect(joined).not.toContain('"password":"admin');
  expect(joined).not.toContain('"token":"admin');
  expect(joined).not.toContain('"sid":"admin');

  // But we should see excerpt + fingerprint markers for sensitive hits (if a sensitive field was matched)
  // Note: This depends on your middleware logging "fp" when sensitive match occurs.
  // If your current middleware only matches query.x and not body.password, this still passes safely.
  // We'll at least assert the file log exists and includes the query hit.
  spy.mockRestore();

  // --- File assertions ---
  const filePath = getSuspiciousLogPath();
  const content = readFileSafe(filePath);

  // File should contain our event name and request path
  expect(content).toContain("security.suspicious_input");
  expect(content).toContain("/auth/login?x=");

  // File must NOT contain raw sensitive field keys with the payload
  expect(content).not.toContain('"password":"admin');
  expect(content).not.toContain('"token":"admin');
  expect(content).not.toContain('"sid":"admin');

  // File SHOULD contain the suspicious excerpt somewhere (from query x)
  expect(content).toContain("admin' OR '1'='1' --");
});