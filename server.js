const app = require("./app.js");
const PORT = 8080;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/`);
  console.log(`JWKS: http://localhost:${PORT}/.well-known/jwks.json`);
  console.log(`Authentication: http://localhost:${PORT}/auth\n`);
});
