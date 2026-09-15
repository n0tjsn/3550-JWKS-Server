const http = require('http')
const port = 8080

const server = http.createServer(function(req, res) {
    res.end('Hello World!')
})

server.listen(port, function(error) {
    console.log("Server running on " + port)
})