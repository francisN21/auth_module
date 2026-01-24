const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");

afterAll(async () => {
  // close DB pool so Jest exits cleanly
  await pool.end();
});

test("GET /health returns ok", async () => {
  const res = await request(app).get("/health");
  expect(res.statusCode).toBe(200);
  expect(res.body.ok).toBe(true);
  expect(res.body.service).toBe("auth_module");
});

test("GET /health/db returns db ok", async () => {
  const res = await request(app).get("/health/db");
  expect(res.statusCode).toBe(200);
  expect(res.body.ok).toBe(true);
  expect(res.body.db).toBe(1);
});
