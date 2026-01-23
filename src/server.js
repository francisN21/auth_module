// src/server.js
require("dotenv").config();

const express = require("express");

const app = express();

// middleware to parse JSON bodies
app.use(express.json());

// basic test route
app.get("/health", (req, res) => {
  res.status(200).json({ ok: true, service: "auth_module" });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
