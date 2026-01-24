// middleware/suspiciousInputLogger.js
const MAX_LEN = 200;

const patterns = [
  /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  /--|\/\*|\*\//,
  /;\s*(drop|alter|create|truncate|insert|update|delete)\b/i,
  /\bunion\b\s+\bselect\b/i,
];

const SENSITIVE_KEYS = new Set([
  "password",
  "pass",
  "pwd",
  "token",
  "access_token",
  "refresh_token",
  "authorization",
  "cookie",
  "sid",
  "session",
]);

function truncate(s) {
  return s.length > MAX_LEN ? s.slice(0, MAX_LEN) + "…(truncated)" : s;
}

function flattenStringsKeyed(obj, out = []) {
  if (!obj) return out;

  if (typeof obj === "string") {
    // no key context here; only used for query/params objects where keys are handled below
    out.push(obj);
    return out;
  }

  if (Array.isArray(obj)) {
    obj.forEach((v) => flattenStringsKeyed(v, out));
    return out;
  }

  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      const key = String(k).toLowerCase();
      if (SENSITIVE_KEYS.has(key)) continue;

      if (typeof v === "string") out.push(v);
      else flattenStringsKeyed(v, out);
    }
  }

  return out;
}

function suspiciousInputLogger(req, res, next) {
  try {
    // We inspect query/params always; for body we skip sensitive keys via the keyed flattener
    const values = [
      ...flattenStringsKeyed(req.query),
      ...flattenStringsKeyed(req.params),
      ...flattenStringsKeyed(req.body),
    ].filter((v) => typeof v === "string");

    const hits = [];
    for (const v of values) {
      for (const re of patterns) {
        if (re.test(v)) {
          hits.push({ pattern: re.toString(), sample: truncate(v) });
          break;
        }
      }
    }

    if (hits.length) {
      (req.log || console).warn(
        {
          event: "security.suspicious_input",
          path: req.originalUrl,
          method: req.method,
          ip: req.ip,
          userAgent: req.get("user-agent"),
          hits,
        },
        "Suspicious input detected"
      );

      // Allow Jest to assert logging without needing to intercept pino
      if (process.env.NODE_ENV === "test") {
        console.warn("security.suspicious_input", { path: req.originalUrl, hits });
      }
    }
  } catch {
    // never block
  }

  next();
}

module.exports = { suspiciousInputLogger };
