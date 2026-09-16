// Import Node.js modules
const app = require("express")(); //web framework
const crypto = require("crypto"); //RSA key pair generation
const PORT = 8080;

// Genereate RSA key pairs
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
const timestamp = Math.floor(Date.now() / 1000); //timestamp

// Convert public key to JWK
const jwk = crypto.createPublicKey(publicKey).export({
  format: "jwk",
});
jwk.use = "sig";
jwk.alg = "RS256";

const key = {
  kid: kid,
  publicKey: publicKey,
  privateKey: privateKey,
  jwk: jwk,
  expiresAt: timestamp + 3600,
};

// JWKS endpoint: returns non-expired RSA keys
app.get("/.well-known/jwks.json", (req, res) => {
  const now = Math.floor(Date.now() / 1000);

  // Checks if the key is expired before serving
  if (key.expiresAt > now) {
    res.json({
      keys: [key.jwk],
    });
  } else {
    res.json({
      keys: [],
    });
  }
});

// Authentication endpoint: returns unexpired, signed JWT
app.post("/auth", (req, res) => {
  res.send("Authentication endpoint");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
