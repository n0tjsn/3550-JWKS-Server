// Import Node.js modules
const app = require("express")(); // Framework for HTTP server
const jwt = require("jsonwebtoken"); // Generates JWTs
const sqlite = require("sqlite3").verbose(); // SQLite database for storing
const crypto = require("crypto"); // Public key generation
const { validKey, expiredKey, anotherKey, allKeys } = require("./keys"); // Imports from keys.js

//Create and/or open database for private keys based on provided table schema
const db = new sqlite.Database("totally_not_my_privateKeys.db");
const tableQuery = `
  CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`;
// Execute query to create/open database
db.exec(tableQuery);

// Prepare SQL query to safely insert data into database without potential for SQL intection
const insertQuery = db.prepare("INSERT INTO keys (key, exp) VALUES (?, ?)");

// Write all private keys and expiry to database. The kid is incremented automatically from 1
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

// JWKS endpoint: returns non-expired RSA keys from database
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    // Timestamp for the current time to compare with exp
    const now = Math.floor(Date.now() / 1000);

    // Prepare query to safely read all keys where exp is greater than the current time (i.e not expired yet)
    const getQuery = db.prepare("SELECT * FROM keys WHERE exp > ?");

    // Runs the query based on the current time
    getQuery.all([now], (err, rows) => {
      if (err) {
        return res.status(500).send("ERROR: Failed to issue key set");
      }

      // Creates new public key from the returned private key and adds it to valid
      const validKeys = rows.map((row) => ({
        ...crypto.createPublicKey(row.key).export({
          format: "jwk",
        }),
        use: "sig",
        alg: "RS256",
        kid: String(row.kid),
      }));

      // Respond with JSON containing valid JWKs
      res.json({ keys: validKeys });
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

// Authentication endpoint: issues JWTs from database
app.post("/auth", (req, res) => {
  try {
    // Checks for existence of "expired" in query to determine if client requested expired token with expired key
    const queryExpired = req.query.expired !== undefined;

    // Timestamp for the current time to compare with exp
    const now = Math.floor(Date.now() / 1000);

    // Prepare query to read data from database based on when the requested query expired:
    const postQuery = queryExpired
      ? "SELECT * FROM keys WHERE exp <= ? LIMIT 1" // If the query is expired, read one expired key.
      : "SELECT * FROM keys WHERE exp > ? LIMIT 1"; // Else (unexpired), read one valid key

    // Runs the query based on the current timestamp (now)
    db.get(postQuery, [now], (err, row) => {
      if (err) {
        return res.status(500).send("ERROR: Failed to issue token");
      }

      // Generates signed JWT with algorithm, key, and expiration timestamp
      const token = jwt.sign({ user: "Lorem Ipsum" }, row.key, {
        algorithm: "RS256",
        keyid: String(row.kid),
        expiresIn: row.exp - now,
      });
      // Respond with JWT
      res.json({ token });
    });
  } catch (error) {
    res.status(500).send("ERROR: Failed to issue token");
  }
});

// Exports API
module.exports = { app, validKey, expiredKey, anotherKey };
