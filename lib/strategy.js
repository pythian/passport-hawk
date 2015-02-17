/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , hawk = require('hawk');

var xtend = require('xtend');


/**
 * `Strategy` constructor.
 *
 * The HTTP Hawk authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field or
 * `hawk` query parameter.
 *
 * Applications must supply a `verify` callback which accepts an `id` and
 * then calls the `done` callback supplying a `credentials` object which
 * should contains a `key` property matching the MAC, an `algorithm`
 * property and a `user` property.
 * If the user is not valid return false
 * `false` as the user.
 *
 * Options:
 *
 *   - `sslTerminated`  whether or not SSL is terminated via a proxy and not used internally, defaults to false
 *
 * Examples:
 *
 *     passport.use(new HawkStrategy(
 *       function(id, done) {
 *         User.findById({ _id: id }, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} [options]
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  options = xtend({}, options, { sslTerminated: options.sslTerminated || false });
  this.options = options;

  if (!verify) throw new Error('HTTP Hawk authentication strategy requires a verify function');
  this.verify = verify;
  this.bewit = false;
  passport.Strategy.call(this);
}


/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request based on the contents of a HTTP Hawk authorization
 * header or query string parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  //express change req.url when mounting with app.use
  //this creates a new request object with url = originalUrl
  req = xtend({}, req, { url: req.originalUrl || req.url });

  var clean = req.headers['authorization'];
  req.headers['authorization'] = clean.replace(', ext=""','');

  var options = {};
  if (this.options.sslTerminated) {
      options.port = 443;
  };

  hawk.server.authenticate(req, this.verify, options, function(err, credentials, artifacts) {
    if (err && err.isMissing) {
      return this.error('Missing authentication tokens');
    }

    if (err && err.message === 'Missing credentials') {
      return this.error('Invalid authentication tokens');
    }

    var payload = (!err ? 'Hello ' + artifacts.ext : 'Invalid User');

    req._hawkHeader = hawk.server.header(credentials, artifacts, {
      payload: payload,
      contentType: 'text/plain'
    });

    if (err && err.message) {
      return this.error(err.message); // Return hawk error
    }

    if (err) {
      return this.error(err); // Error String (bad use of errors).
    }

    this.success(credentials.user, artifacts);
  }.bind(this));
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
