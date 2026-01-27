const fs = require("fs");
const path = require("path");

// Set test-only paths BEFORE app import
process.env.SUSPICIOUS_IPS_PATH = path.join(process.cwd(), "log", "suspiciousIps.test.json");
// Optional: ensure suspicious payload file doesn't interfere (if you also write it)
process.env.SUSPICIOUS_LOG_PATH = path.join(process.cwd(), "log", "suspiciousInput.test.txt");

const request = require("supertest");
const { app } = require("../src/app");
const { pool } = require("../src/db");

function readJsonSafe(p) {
  try {
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, "utf8");
    return raw.trim() ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

beforeEach(() => {
  // Reset test files
  fs.mkdirSync(path.join(process.cwd(), "log"), { recursive: true });
  fs.writeFileSync(process.env.SUSPICIOUS_IPS_PATH, "{}", "utf8");
  fs.writeFileSync(process.env.SUSPICIOUS_LOG_PATH, "", "utf8");
});

afterAll(async () => {
  await pool.end();
});

test("throttles suspicious payload logging after 5 events per minute per IP and records IP stats", async () => {
  const spy = jest.spyOn(console, "warn").mockImplementation(() => {});
  const ip = "203.0.113.9"; // test IP
  const payload = encodeURIComponent("admin' OR '1'='1' --");

  // Send 10 requests from the same IP
  for (let i = 0; i < 10; i++) {
    await request(app)
      .get(`/health?x=${payload}`)
      .set("X-Forwarded-For", ip);
  }

  // Count how many times we logged the payload event.
  // We only count the "Suspicious input detected" message line to avoid counting throttle notices.
  const payloadLogs = spy.mock.calls.filter((call) => {
    // call is like: ["security.suspicious_input", {...}] (test hook) OR
    // [obj, "Suspicious input detected"] (pino/console warn style)
    const asString = call.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
    return asString.includes("Suspicious input detected");
  });

  expect(payloadLogs.length).toBe(5);

  spy.mockRestore();
  // Give the throttle store time to flush JSON to disk (it batches writes)
  await new Promise((r) => setTimeout(r, 2200));

  // Verify JSON file contains the IP with count > 5 and blockedUntil set
  const data = readJsonSafe(process.env.SUSPICIOUS_IPS_PATH);
  expect(data).toBeTruthy();
  //   expect(data[ip]).toBeTruthy();

  // Key might be stored as "203.0.113.9" or "::ffff:203.0.113.9"
  const key = Object.keys(data).find((k) => k === ip || k.endsWith(ip));
  expect(key).toBeTruthy();

  const s = data[key];
  expect(typeof s.count).toBe("number");
  expect(s.count).toBeGreaterThan(5);

  expect(typeof s.blockedUntil).toBe("number");
  expect(s.blockedUntil).toBeGreaterThan(Date.now());

  expect(typeof s.totalCount).toBe("number");
  expect(s.totalCount).toBeGreaterThanOrEqual(10);
});