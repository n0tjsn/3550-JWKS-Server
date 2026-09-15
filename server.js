//Import Node.js modules
const app = require('express')()    //web framework
const crypto = require('crypto')    //RSA key pair generation
const PORT = 8080

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
})

const kid = crypto.randomUUID()
const timestamp = Math.floor(Date.now() / 1000)

console.log(publicKey);
console.log(privateKey);
console.log(`kid: ${kid}`)
console.log(`timestamp: ${timestamp}\n`)

app.get('/', (req, res) => {
    res.send(`Server running on port ${PORT}`)
})

//RESTful JWKS endpoint: serves non-expired keys 
app.get('/jwks', (req, res) => {
    res.send('JWKS endpoint')
})

//Authentication endpoint: returns unexpired, signed JWT
app.post('/auth', (req, res) => {
    res.send('Authentication endpoint')
})

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`)
})