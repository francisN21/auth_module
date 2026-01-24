const MAX_LEN = 200;

const patterns = [
  /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, // OR 1=1
  /--|\/\*|\*\//,                                         // SQL comments
  /;\s*(drop|alter|create|truncate|insert|update|delete)\b/i,
  /\bunion\b\s+\bselect\b/i,
];

function truncate(s) {
  return s.length > MAX_LEN ? s.slice(0, MAX_LEN) + "…(truncated)" : s;
}

function flattenStrings(x, out = []) {
  if (!x) return out;
  if (typeof x === "string") out.push(x);
  else if (Array.isArray(x)) x.forEach(v => flattenStrings(v, out));
  else if (typeof x === "object") Object.values(x).forEach(v => flattenStrings(v, out));
  return out;
}

function suspiciousInputLogger(req, res, next) {
  try {
    const values = [
      ...flattenStrings(req.query),
      ...flattenStrings(req.params),
      ...flattenStrings(req.body),
    ];

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
      // req.log exists because of pino-http
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
    }
  } catch {
    // never block requests if logging fails
  }

  next();
}

module.exports = { suspiciousInputLogger };