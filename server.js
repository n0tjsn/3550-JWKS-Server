const app = require('express')()
const PORT = 8080

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