const request = require("supertest");
const server = require("../app");
var assert = require('chai').assert;


describe("Test Express", function() {

  after(function (done) {
    process.exit()
});

  it("test", function(done) {
    request(server)
      .get("/")
      .expect(200)
      .end(function(err, res) {
        if (err) throw err;
        assert.isTrue(res.text === "Welcome to Test Express!") 
        done()
      });
  });
  it("Eval Injection", function(done) {
    request(server)
      .get("/evalDemo?preTax=0")
      .expect(200)
      .end(function(err, res) {
        if (err) throw err;
        assert.isTrue(res.text === "This is eval demo for TestExpress application!") 
        done()
      });
  });
});

