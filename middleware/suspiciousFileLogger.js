const fs = require("fs");
const path = require("path");

function getSuspiciousLogPath() {
  return process.env.SUSPICIOUS_LOG_PATH ||
    path.join(process.cwd(), "log", "suspiciousInput.txt");
}

function appendSuspiciousEvent(eventObj) {
  const filePath = getSuspiciousLogPath();
  const dir = path.dirname(filePath);

  fs.mkdirSync(dir, { recursive: true });

  // JSONL: one JSON object per line (easy to parse later)
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    ...eventObj,
  }) + "\n";

  fs.appendFileSync(filePath, line, { encoding: "utf8" });
}

module.exports = { appendSuspiciousEvent, getSuspiciousLogPath };
