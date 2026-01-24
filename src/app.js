// src/app.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const authRouter = require("../routes/auth");
const { notFound } = require("../middleware/notFound");
const { errorHandler } = require("../middleware/errorHandler");
const { pool } = require("./db");

const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:3000";
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  })
);

app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "auth_module" });
});

app.get("/health/db", async (req, res, next) => {
  try {
    const r = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: r.rows[0].ok });
  } catch (e) {
    next(e);
  }
});

app.use("/auth", authRouter);

app.use(notFound);
app.use(errorHandler);

module.exports = { app };
