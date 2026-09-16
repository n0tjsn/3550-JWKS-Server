// Import Node.js modules
const app = require("express")(); //web framework
const crypto = require("crypto"); //RSA key pair generation
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

  const kid = crypto.randomUUID(); //key ID

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

const now = Math.floor(Date.now() / 1000); // timestamp for current time

//generate two keys, one expired and one valid, and puts them in an array
const key1 = generateKey(now + 3600);
const key2 = generateKey(now + 3600);
const keys = [key1, key2];

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
  const now = Math.floor(Date.now() / 1000);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/`);
  console.log(`JWKS: http://localhost:${PORT}/.well-known/jwks.json`);
  console.log(`Authentication: http://localhost:${PORT}/auth`);
});
