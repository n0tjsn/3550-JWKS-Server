// Import Node.js modules
const app = require("express")();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const PORT = 8080;

// Genereate RSA key pairs
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

  //key ID for identifying RSA keys
  const kid = crypto.randomUUID();

  // Convert public key to JWK
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
  };
}

// timestamp for current time
const now = Math.floor(Date.now() / 1000);

// generate two keys, one expired and one valid.
const validKey = generateKey(now + 3600);
const expiredKey = generateKey(now - 3600);
const keys = [validKey, expiredKey];

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  const now = Math.floor(Date.now() / 1000);

  //filters out the non-expired keys into validKeys
  const validKeys = keys.filter((key) => key.expiry > now);

  res.json({
    keys: validKeys.map((key) => key.jwk),
  });
});

// Authentication endpoint: issues JWTs to the user
app.post("/auth", (req, res) => {
  // checks for "expired" in URL
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

  // responds with JWT
  res.json({ token });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/`);
  console.log(`JWKS: http://localhost:${PORT}/.well-known/jwks.json`);
  console.log(`Authentication: http://localhost:${PORT}/auth\n`);
});
