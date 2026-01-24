const crypto = require("crypto");

const MAX_EXCERPT = 120;

// Patterns you care about (add more later)
const patterns = [
  { name: "or_true", re: /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i }, // OR '1'='1'
  { name: "sql_comment", re: /--|\/\*|\*\// },
  { name: "union_select", re: /\bunion\b\s+\bselect\b/i },
  { name: "ddl_dml", re: /;\s*(drop|alter|create|truncate|insert|update|delete)\b/i },
];

// Fields we consider sensitive (we never log full values)
const SENSITIVE_KEYS = new Set([
  "password",
  "pass",
  "pwd",
  "token",
  "access_token",
  "refresh_token",
  "sid",
  "session",
]);

function fingerprint(value) {
  // short fingerprint for correlation (doesn't reveal the secret)
  return crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

function excerptAroundMatch(value, matchIndex, matchLen) {
  const start = Math.max(0, matchIndex - 30);
  const end = Math.min(value.length, matchIndex + matchLen + 30);
  let out = value.slice(start, end);
  // normalize whitespace to keep logs clean
  out = out.replace(/\s+/g, " ");
  if (out.length > MAX_EXCERPT) out = out.slice(0, MAX_EXCERPT) + "…";
  return out;
}

function collectStringFields(obj, prefix = "", out = []) {
  if (!obj || typeof obj !== "object") return out;

  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v == null) continue;

    if (typeof v === "string") out.push({ key, value: v });
    else if (Array.isArray(v)) {
      v.forEach((item, idx) => {
        if (typeof item === "string") out.push({ key: `${key}[${idx}]`, value: item });
        else if (item && typeof item === "object") collectStringFields(item, `${key}[${idx}]`, out);
      });
    } else if (typeof v === "object") {
      collectStringFields(v, key, out);
    }
  }
  return out;
}

function suspiciousInputLogger(req, res, next) {
  try {
    // Gather candidate strings from query/params/body
    const candidates = [
      ...collectStringFields(req.query, "query"),
      ...collectStringFields(req.params, "params"),
      ...collectStringFields(req.body, "body"),
    ];

    const hits = [];

    for (const { key, value } of candidates) {
      for (const { name, re } of patterns) {
        const m = re.exec(value);
        if (!m) continue;

        const fieldName = key.split(".").slice(-1)[0].toLowerCase();
        const isSensitive = SENSITIVE_KEYS.has(fieldName);

        hits.push({
          field: key,
          pattern: name,
          sensitive: isSensitive,
          // If sensitive, DO NOT log the whole value. Log only an excerpt around the match + fingerprint.
          ...(isSensitive
            ? {
                excerpt: excerptAroundMatch(value, m.index, m[0].length),
                fp: fingerprint(value),
              }
            : {
                excerpt: excerptAroundMatch(value, m.index, m[0].length),
              }),
        });

        break; // one hit per field is enough
      }
    }

    if (hits.length) {
      const logObj = {
        event: "security.suspicious_input",
        path: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get("user-agent"),
        hits,
      };

      (req.log || console).warn(logObj, "Suspicious input detected");

      // Let Jest assert it easily
      if (process.env.NODE_ENV === "test") {
        console.warn("security.suspicious_input", logObj);
      }
    }
  } catch {
    // never block
  }

  next();
}

module.exports = { suspiciousInputLogger };
