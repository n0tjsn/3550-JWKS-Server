const request = require("supertest");
const jwt = require("jsonwebtoken");
const { app, validKey, expiredKey } = require("../app.js");

describe("JWKS endpoint", () => {
  test("GET returns status code 200 when response successfully sends", async () => {
    const res = await request(app).get("/.well-known/jwks.json"); // sends GET request
    expect(res.status).toBe(200); // expects response to return 200 OK code
  });

  test("GET returns status code 500 when response fails to send ", async () => {
    const mockJSON = jest
      .spyOn(app.response, "json")
      .mockImplementationOnce(() => {
        throw new Error("Simulated response failure");
      });

    const res = await request(app).get("/.well-known/jwks.json"); // sends GET request
    expect(res.status).toBe(500); // expects response to return 500 error code

    // restore res.json to original function
    mockJSON.mockRestore();
  });

  test("GET returns JWKS array", async () => {
    const res = await request(app).get("/.well-known/jwks.json");
    expect(Array.isArray(res.body.keys)).toBe(true); // expects response (JWKS) to be an array
  });

  test("JWKS only contains unexpired keys", async () => {
    const res = await request(app).get("/.well-known/jwks.json");
    const now = Math.floor(Date.now() / 1000);
    const exp = res.body.keys.map((key) => key.exp); // stores key IDs from keys in JWKS

    // expects kids to only contain the valid kid and not the expired kid
    expect(exp).toBeLessThan(now);
  });
});

describe("AUTH endpoint", () => {
  test("POST returns status code 200 with successful signing", async () => {
    const res = await request(app).post("/auth"); // sends POST request
    expect(res.status).toBe(200);
  });

  test("POST returns error code 500 with failed signing", async () => {
    // simulates an error to throw by replacing jwt.sign with a mock function
    const mockSign = jest.spyOn(jwt, "sign").mockImplementation(() => {
      throw new Error("Simulated signing failure");
    });

    const res = await request(app).post("/auth");
    expect(res.status).toBe(500);

    // restores jwt.sign to original funciton
    mockSign.mockRestore();
  });

  test("POST issues JWT with valid JWKS key when given valid '/auth query", async () => {
    const authRes = await request(app).post("/auth");
    const decoded = jwt.decode(authRes.body.token, { complete: true }); // decodes JWT returned from POST request

    const jwksRes = await request(app).get("/.well-known/jwks.json");
    const jwksKids = jwksRes.body.keys.map((key) => key.kid);

    expect(jwksKids).toContain(decoded.header.kid); // expects jwksKids to contain key ID from decoded JWT
  });

  test("POST issues expired or valid JWT based on given query", async () => {
    const expiredRes = await request(app).post("/auth?expired");
    const expired = jwt.decode(expiredRes.body.token, { complete: true });

    const validRes = await request(app).post("/auth");
    const valid = jwt.decode(validRes.body.token, { complete: true });

    const now = Math.floor(Date.now() / 1000); // gets current timestamp

    expect(expired.payload.exp).toBeLessThan(now); //expects JWT to be expired
    expect(valid.payload.exp).toBeGreaterThan(now); //expects JWT to be expired
  });
});
