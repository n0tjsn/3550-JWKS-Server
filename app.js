// Import Node.js modules
const app = require("express")();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// Generates RSA key pairs
function generateKey(expiration) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  // Key ID for identifying RSA keys
  const kid = crypto.randomUUID();

  // Creates JWK fron public key
  const jwk = crypto.createPublicKey(publicKey).export({
    format: "jwk",
  });
  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = kid;

  return {
    kid: kid,
    publicKey: publicKey,
    privateKey: privateKey,
    jwk: jwk,
    expiry: expiration,
    // status: expiration < now ? "expired" : "valid",
  };
}

// Timestamp in seconds
const now = Math.floor(Date.now() / 1000);

// Generate two keys, one expired and one valid.
const validKey = generateKey(now + 3600);
const expiredKey = generateKey(now - 3600);
const anotherKey = generateKey(now - 1000);
const keys = [validKey, expiredKey, anotherKey];

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  const now = Math.floor(Date.now() / 1000);

  // Filters out the non-expired keys into validKeys
  const validKeys = keys.filter((key) => key.expiry > now);

  res.json({
    keys: validKeys.map((key) => key.jwk),
  });
});

// Authentication endpoint: issues JWTs
app.post("/auth", (req, res) => {
  // Checks for "expired" in query
  const queryExpired = req.query.expired !== undefined;
  const key = queryExpired ? expiredKey : validKey;

  // Generates JWT
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
});

module.exports = { app, validKey, expiredKey, anotherKey };
