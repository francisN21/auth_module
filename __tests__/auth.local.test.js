const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");
const { resetDb } = require("./helpers/dbReset");


beforeEach(async () => {
  await resetDb();
});

afterAll(async () => {
  await pool.end();
});

test("signup sets session cookie and returns user", async () => {
  const res = await request(app)
    .post("/auth/signup")
    .set("Content-Type", "application/json")
    .send({ email: "test@example.com", password: "Password123!" });

  expect(res.statusCode).toBe(201);
  expect(res.body.ok).toBe(true);
  expect(res.body.user.email).toBe("test@example.com");

  const setCookie = res.headers["set-cookie"];
  expect(setCookie).toBeDefined();
  expect(setCookie.join(";")).toMatch(/sid=/); // uses your SESSION_COOKIE_NAME if still "sid"
});

test("/auth/me requires auth", async () => {
  const res = await request(app).get("/auth/me");
  expect(res.statusCode).toBe(401);
  expect(res.body.ok).toBe(false);
});

test("me works after signup (cookie auth)", async () => {
  const signup = await request(app)
    .post("/auth/signup")
    .send({ email: "test@example.com", password: "Password123!" });

  const cookie = signup.headers["set-cookie"];
  expect(cookie).toBeDefined();

  const me = await request(app).get("/auth/me").set("Cookie", cookie);
  expect(me.statusCode).toBe(200);
  expect(me.body.ok).toBe(true);
  expect(me.body.user.email).toBe("test@example.com");
});

test("logout clears session", async () => {
  const signup = await request(app)
    .post("/auth/signup")
    .send({ email: "test@example.com", password: "Password123!" });

  const cookie = signup.headers["set-cookie"];

  const out = await request(app).post("/auth/logout").set("Cookie", cookie);
  expect(out.statusCode).toBe(200);
  expect(out.body.ok).toBe(true);

  const me = await request(app).get("/auth/me").set("Cookie", cookie);
  expect(me.statusCode).toBe(401);
});
