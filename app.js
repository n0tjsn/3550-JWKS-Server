// Import Node.js modules
const app = require("express")(); // Framework for HTTP server
const jwt = require("jsonwebtoken"); // JWT
const { validKey, expiredKey, anotherKey, allKeys } = require("./keys"); // Imports from keys.js

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    // Populates validKeys array with non-expired keys
    // Timestamp for comparing with key expiries
    const now = Math.floor(Date.now() / 1000);
    // Filters out the non-expired keys into validKeys
    const validKeys = allKeys.filter((key) => key.expiry > now);

    // Returns JSON containing valid JWKs from validKeys
    res.json({
      keys: validKeys.map((key) => key.jwk),
    });
  } catch (error) {
    // Catches error and returns JSON containing error message
    res.status(500).json("ERROR: Failed to issue key set");
  }
});

// Authentication endpoint: issues JWTs
app.post("/auth", (req, res) => {
  try {
    // Checks for existence of "expired" in query to determine if client requested expired token with expired key
    const queryExpired = req.query.expired !== undefined;
    const key = queryExpired ? expiredKey : validKey;

    // Calculates expiry for token
    const now = Math.floor(Date.now() / 1000);
    const secUntilExpiry = key.expiry - now;

    // Generates JWT with algorithm, key, and expiration timestamp
    const token = jwt.sign({ sub: "Lorem Ipsum" }, key.privateKey, {
      algorithm: "RS256",
      keyid: key.kid,
      expiresIn: secUntilExpiry,
    });

    console.log(
      `${queryExpired ? "EXPIRED" : "VALID"}\t\t keyID: ${key.kid} \t expiry: ${key.expiry}`,
    );

    // Responds with JWT
    res.json({ token });
  } catch (error) {
    res.status(500).json("ERROR: Failed to issue token");
  }
});

// Exports API to server.js
module.exports = { app, validKey, expiredKey, anotherKey };
