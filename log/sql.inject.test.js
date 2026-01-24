const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");

afterAll(async () => {
  await pool.end();
});

test("logs suspicious SQLi-like input in query string", async () => {
  const spy = jest.spyOn(console, "warn").mockImplementation(() => {});

  // classic payload
  const payload = "admin' OR '1'='1' --";
  const encoded = encodeURIComponent(payload);

  const res = await request(app).get(`/health?x=${encoded}`);
  expect(res.statusCode).toBe(200);

  // We expect our middleware to emit a console.warn in test env
  expect(spy).toHaveBeenCalled();

  // Optional: verify what was logged (structure)
  const calls = spy.mock.calls.map((c) => c.join(" "));
  const matched = calls.some((s) => s.includes("security.suspicious_input"));
  expect(matched).toBe(true);

  spy.mockRestore();
});
