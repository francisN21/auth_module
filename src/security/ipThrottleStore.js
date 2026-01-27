// src/security/ipThrottleStore.js
const fs = require("fs");
const path = require("path");

const DEFAULTS = {
  windowMs: 60_000, // 1 minute
  limit: 5, // 5 suspicious logs per window
  blockMs: 5 * 60_000, // block logging for 5 minutes once exceeded
  pruneAfterMs: 24 * 60 * 60_000, // keep IPs for 24h in file/memory
  flushEveryMs: 2000, // batch disk writes every ~2s (non-test only)
};

function now() {
  return Date.now();
}

function getThrottlePath() {
  return (
    process.env.SUSPICIOUS_IPS_PATH ||
    path.join(process.cwd(), "log", "suspiciousIps.json")
  );
}

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function loadJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return {};
    const raw = fs.readFileSync(filePath, "utf8");
    if (!raw.trim()) return {};
    return JSON.parse(raw);
  } catch {
    // If corrupt, don't crash the app. Start fresh.
    return {};
  }
}

function writeJsonAtomic(filePath, obj) {
  ensureDir(filePath);
  const tmp = filePath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf8");
  fs.renameSync(tmp, filePath);
}

class IpThrottleStore {
  constructor(options = {}) {
    this.cfg = { ...DEFAULTS, ...options };
    this.filePath = getThrottlePath();

    this.map = new Map(); // ip -> state
    this._loaded = false;

    this._dirty = false;
    this._flushTimer = null;

    // In tests: never create timers; flush immediately so Jest can exit cleanly
    this._noTimers = process.env.NODE_ENV === "test";
  }

  _lazyLoad() {
    if (this._loaded) return;
    const data = loadJsonSafe(this.filePath);
    for (const [ip, state] of Object.entries(data)) {
      this.map.set(ip, state);
    }
    this._loaded = true;
    this.prune();
  }

  _flushNow() {
    if (!this._dirty) return;
    this._dirty = false;
    const obj = Object.fromEntries(this.map.entries());
    writeJsonAtomic(this.filePath, obj);
  }

  _scheduleFlush() {
    if (this._noTimers) {
      // Flush immediately (no timers) so Jest can exit cleanly
      this._flushNow();
      return;
    }

    if (this._flushTimer) return;

    this._flushTimer = setTimeout(() => {
      this._flushTimer = null;
      this._flushNow();
    }, this.cfg.flushEveryMs);

    // Don't keep the process alive just for this timer (nice for CLIs/dev)
    if (typeof this._flushTimer.unref === "function") this._flushTimer.unref();
  }

  prune() {
    this._lazyLoad(); // safe if already loaded

    const t = now();
    const cutoff = t - this.cfg.pruneAfterMs;

    for (const [ip, s] of this.map.entries()) {
      const lastSeen = s.lastSeen || s.windowStart || 0;
      if (lastSeen < cutoff) this.map.delete(ip);
    }

    this._dirty = true;
    this._scheduleFlush();
  }

  /**
   * Record a suspicious attempt and return whether logging should be allowed.
   * allowed: true -> you can log this event
   * allowed: false -> logging for this IP is throttled
   */
  hit(ip) {
    this._lazyLoad();

    const t = now();
    const s = this.map.get(ip) || {
      ip,
      windowStart: t,
      count: 0,
      blockedUntil: 0,
      lastSeen: t,
      totalCount: 0,
    };

    s.lastSeen = t;

    // If currently blocked, keep counting totals but deny logging
    if (s.blockedUntil && t < s.blockedUntil) {
      s.totalCount += 1;
      this.map.set(ip, s);
      this._dirty = true;
      this._scheduleFlush();
      return { allowed: false, state: s, reason: "blocked" };
    }

    // Window rollover
    if (t - s.windowStart >= this.cfg.windowMs) {
      s.windowStart = t;
      s.count = 0;
    }

    s.count += 1;
    s.totalCount += 1;

    // Exceeded limit -> block
    if (s.count > this.cfg.limit) {
      s.blockedUntil = t + this.cfg.blockMs;
      this.map.set(ip, s);
      this._dirty = true;
      this._scheduleFlush();
      return { allowed: false, state: s, reason: "rate_limited" };
    }

    // Allowed
    this.map.set(ip, s);
    this._dirty = true;
    this._scheduleFlush();
    return { allowed: true, state: s, reason: "ok" };
  }

  /**
   * Call on process shutdown if you want a clean flush + no pending timers.
   * Not strictly required, but good hygiene.
   */
  shutdown() {
    if (this._flushTimer) {
      clearTimeout(this._flushTimer);
      this._flushTimer = null;
    }
    this._flushNow();
  }
}

module.exports = { IpThrottleStore, getThrottlePath };
