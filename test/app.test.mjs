import request from "supertest";
import { expect } from "chai";
import app from "../index.mjs";

describe("Auth System", () => {
  let server;

  before((done) => {
    server = app.listen(4000, () => {
      console.log("Test server is running");
      done();
    });
  });

  after((done) => {
    server.close(() => {
      console.log("Test server stopped");
      done();
    });
  });

  it("Register a new user", (done) => {
    request(server)
      .post("/register")
      .send({
        username: "Shubham",
        email: "shubham@gmail.com",
        password: "abcd",
      })
      .expect(201, done);
  });

  it("User already exist", (done) => {
    request(server)
      .post("/register")
      .send({
        username: "Shubham",
        email: "shubham@gmail.com",
        password: "abcd",
      })
      .expect(400, done);
  });

  it("login a user and return a token", (done) => {
    request(server)
      .post("/login")
      .send({ email: "shubham@gmail.com", password: "abcd" })
      .expect(200)
      .expect((res) => {
        if (!res.body.token) throw new Error("Token not found");
      })
      .end(done);
  });

  it("Invalid credentials", (done) => {
    request(server)
      .post("/login")
      .send({ email: "shubham@gmail.com", password: "wrongpassword" })
      .expect(400, done);
  });

  it("get user with valid token", (done) => {
    request(server)
      .post("/login")
      .send({ email: "shubham@gmail.com", password: "abcd" })
      .end((err, res) => {
        if (err) return done(err);

        const token = res.body.token;

        request(server)
          .get("/profile")
          .set("Authorization", `Bearer ${token}`)
          .expect(200)
          .expect((res) => {
            if (!res.body.username || !res.body.email)
              throw new Error("User not found");
          })
          .end(done);
      });
  });

  it("user profile not found with invalid token", (done) => {
    request(server)
      .get("/profile")
      .set("Authorization", "Bearer invalidtoken")
      .expect(403, done);
  });
});
