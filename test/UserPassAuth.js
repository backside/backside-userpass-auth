
var UserPassAuth = require("../lib/UserPassAuth")
var assert = require("chai").assert
var bcrypt = require("bcrypt")

function MockStore(data) {
  this.data = data || {} || {} || {} || {}
}
MockStore.prototype.privateGet = function(key, cb) {
  cb(null, this.data[key])
}
MockStore.prototype.privateSet = function(key, val, cb) {
  this.data[key] = val
  this.dataSet(key, val)
  cb()
}
MockStore.prototype.dataSet = function(key, val) {}

describe("UserPassAuth", function() {
  describe("creating a user", function() {
    it("should be able to create a user and then retrieve it", function(done) {
      var mockStore = new MockStore()
      var auth = new UserPassAuth(mockStore)
      var wasCalled = false
      mockStore.dataSet = function() {
        wasCalled = true
      }
      auth.addUser("user1", "password", {name: "guy"}, function(err, details) {
        if (err) return done(err)
        assert.equal(details.username, "user1")
        assert.equal(details.name, "guy")
        auth.userExists("user1", function(err, exists) {
          if (err) return done(err)
          assert(exists)
          assert(wasCalled)
          done()
        })
      })
    })
  })
  describe("auth a user", function() {
    var auth = null
    var mockStore = null
    before(function(done) {
      bcrypt.hash("password", 4, function(err, hash) {
        if (err) return done(err)
        mockStore = new MockStore({
          "/_users/user2" : {
            hash: { value: hash },
            method: { value: "bcrypt" },
            user: {
              value: {
                name: { value: "steve" },
                username: { value: "user2" }
              }
            }
          }
        })
        auth = new UserPassAuth(mockStore)
        done()
      })
    })

    it("should be able auth a user", function(done) {
      auth.loadUser("user2", "password", function(err, good, user) {
        if (err) return done(err)
        assert.equal(good, true)
        assert.equal(user.username, "user2")
        assert.equal(user.name, "steve")
        done()
      })
    })
    it("should fail with a bad password", function(done) {
      auth.loadUser("user2", "badpass", function(err, good, user) {
        if (err) return done(err)
        assert.equal(good, false)
        assert.equal(user, null)
        done()
      })
    })
    it("should fail with a non existant user", function(done) {
      auth.loadUser("user3", "badpass", function(err, good, user) {
        if (err) return done(err)
        assert.equal(good, false)
        assert.equal(user, null)
        done()
      })
    })
  })
  describe("generating tokens", function() {
    it("should be able to generate a token and decode it", function(done) {
      var mockStore = new MockStore()
      var auth = new UserPassAuth(mockStore)
      var token = auth.genToken({user: "user1"})
      auth.decodeToken(token, function(isValid, decoded) {
        assert.equal(isValid, true)
        assert.equal(decoded.user, "user1")
        done()
      })
    })
  })
})
