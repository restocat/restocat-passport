const Framework = require('./Framework');
const {Passport} = require('passport');

const passport = new Passport();

passport.framework(new Framework());

module.exports = passport;

/**
 * Expose constructors.
 */
exports.Framework = Framework;
exports.Passport = exports.Authenticator = Passport;
exports.Strategy = require('passport-strategy');

/**
 * Expose strategies.
 */
exports.strategies = {};