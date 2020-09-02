const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const mongoose = require("mongoose");
const User = mongoose.model("users");
const Pandit = mongoose.model("pandits");

const keys = require("./keys");

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = keys.secretOrKey;

module.exports = (passport) => {
  passport.use(
    new JwtStrategy(opts, (jwt_payload, done) => {
      Pandit.findById(jwt_payload.id)
        .then((pandit) => {
          if (pandit) {
            return done(null, pandit);
          }
          return done(null, false);
        })
        .catch((err) => console.log(err));
    })
  );
};
