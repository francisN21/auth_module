const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");

afterAll(async () => {
  await pool.end();
});

test("does not log password/token/cookie-like values from request body", async () => {
  const spy = jest.spyOn(console, "warn").mockImplementation(() => {});

  // Put SQLi-ish payload into sensitive fields; middleware should NOT log these values
  await request(app)
    .post("/auth/login?x=" + encodeURIComponent("admin' OR '1'='1' --")) // triggers logging via query
    .send({
      email: "test@example.com",
      password: "admin' OR '1'='1' --",
      token: "admin' OR '1'='1' --",
      sid: "admin' OR '1'='1' --",
    });

  // Find the logged payload
  const joined = spy.mock.calls.map((c) => JSON.stringify(c)).join("\n");

  // It should have logged the query param hit (x=...)
  expect(joined).toContain("security.suspicious_input");

  // It must NOT contain the sensitive payload from body fields
  expect(joined).not.toContain('"password":"admin');
  expect(joined).not.toContain('"token":"admin');
  expect(joined).not.toContain('"sid":"admin');

  spy.mockRestore();
});