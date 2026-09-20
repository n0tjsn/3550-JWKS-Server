const crypto = require("crypto"); // JWK and keyID

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
const offsetHour = 3600;

// Generate three keys, one valid and two valid, and stores them in an array of keys.
const validKey = generateKey(now + offsetHour);
const expiredKey = generateKey(now - offsetHour);
const anotherKey = generateKey(now + offsetHour * 2);
const allKeys = [validKey, expiredKey, anotherKey];

module.exports = { validKey, expiredKey, anotherKey, allKeys };
