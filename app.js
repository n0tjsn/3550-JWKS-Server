// Import Node.js modules
const app = require("express")(); // Framework for HTTP server
const jwt = require("jsonwebtoken"); // JWT
const sqlite = require("sqlite3").verbose(); // SQLite
const { validKey, expiredKey, anotherKey, allKeys } = require("./keys"); // Imports from keys.js

//Create and/or open database for private keys
const db = new sqlite.Database("totally_not_my_privateKeys.db");
const tableQuery = `
  CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`;
db.exec(tableQuery);

// Prepare SQL query to safely insert data into database without potential for SQL intection
const insertQuery = db.prepare("INSERT INTO keys (key, exp) VALUES (?, ?)");

// Write ave private keys and expiry to database
allKeys.forEach((k) => {
  insertQuery.run(k.privateKey, k.exp);
});

// Ensures that only GET requests are allowed for /jwks
app.all("/.well-known/jwks.json", (req, res, next) => {
  if (req.method !== "GET") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    // Populates validKeys array with non-expired keys
    // Timestamp for comparing with key expiries
    const now = Math.floor(Date.now() / 1000);
    // Filters out the non-expired keys into validKeys
    const validKeys = allKeys.filter((key) => key.exp > now);

    // Returns JSON containing valid JWKs from validKeys
    res.json({
      keys: validKeys.map((key) => key.jwk),
    });
  } catch (error) {
    // Catches error and returns JSON containing error message
    res.status(500).send("ERROR: Failed to issue key set");
  }
});

// Ensures that only POST requests are allowed for /auth
app.all("/auth", (req, res, next) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

// Authentication endpoint: issues JWTs
app.post("/auth", (req, res) => {
  try {
    // Checks for existence of "expired" in query to determine if client requested expired token with expired key
    const queryExpired = req.query.expired !== undefined;

    // Calculates expiry for token
    const now = Math.floor(Date.now() / 1000);

    // Prepare query to read data from database based on when the requested query expired:
    const postQuery = queryExpired
      ? "SELECT * FROM keys WHERE exp <= ? LIMIT 1" // If the query is expired, read one expired key.
      : "SELECT * FROM keys WHERE exp > ? LIMIT 1"; // Else (unexpired), read one valid key

    // Runs the query based on the current timestamp (now)
    db.get(postQuery, [now], (err, row) => {
      if (err) return res.status(500).send("ERROR: Failed to issue token");

      // Generates signed JWT with algorithm, key, and expiration timestamp
      const token = jwt.sign({ user: "Lorem Ipsum" }, row.key, {
        algorithm: "RS256",
        keyid: String(row.kid),
        expiresIn: row.exp - now,
      });
      // Respond with JWT
      res.send(token);
    });
  } catch (error) {
    res.status(500).send("ERROR: Failed to issue token");
  }
});

// Exports API to server.js
module.exports = { app, validKey, expiredKey, anotherKey };
