const passport = require('passport');
const JwtStrategy = require("passport-jwt").Strategy
const ExtractJWT = require("passport-jwt").ExtractJwt

const db = require("../models")

passport.use(
  new JwtStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    // Customize these
    secretOrKey: "secret",
    issuer: "accounts.examplesoft.com",
    audience: "yoursite.net"
  },
    function (jwt_payload, done) {
      db.User.findOne({ id: jwt_payload.sub }, function (err, user) {
        if (err) {
          return done(err, false)
        }
        if (user) {
          return done(null, user)
        } else {
          return done(null, false)
          // or you could create a new account
        }
      })
    }))

module.exports = passport