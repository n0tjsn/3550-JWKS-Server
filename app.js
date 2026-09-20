// Import Node.js modules
const app = require("express")(); // framework for HTTP server
const crypto = require("crypto"); // JWK and keyID
const jwt = require("jsonwebtoken"); // JWT

// Generates RSA key pairs
function generateKey(expiration) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, // key size
    publicKeyEncoding: {
      type: "spki", //public key encoding scheme
      format: "pem", // formats key as Base64 string
    },
    privateKeyEncoding: {
      type: "pkcs8", // private key encoding scheme
      format: "pem",
    },
  });

  // Key ID for identifying RSA keys
  const kid = crypto.randomUUID();

  // Creates JWK fron public key
  const jwk = crypto.createPublicKey(publicKey).export({
    format: "jwk",
  });
  jwk.use = "sig"; // signature
  jwk.alg = "RS256"; // signing algorithm
  jwk.kid = kid; // key ID

  return {
    // returns key with various attributes
    kid: kid,
    publicKey: publicKey,
    privateKey: privateKey,
    jwk: jwk,
    expiry: expiration,
  };
}

// Timestamp in seconds
const now = Math.floor(Date.now() / 1000);

// Generate three keys, one valid and two valid, and stores them in an array of keys.
const validKey = generateKey(now + 3600);
const expiredKey = generateKey(now - 3600);
const anotherKey = generateKey(now + 1000);
const allKeys = [validKey, expiredKey, anotherKey];

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  try {
    // Populates validKeys array with non-expired keys

    // timestamp for comparing with key expiries
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

    // Generates JWT with algorithm, key, and expiration timestamp
    const token = jwt.sign({ sub: "Lorem Ipsum" }, key.privateKey, {
      algorithm: "RS256",
      keyid: key.kid,
      expiresIn: queryExpired ? -3600 : 3600,
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

// exports API to server.js
module.exports = { app, validKey, expiredKey, anotherKey };
