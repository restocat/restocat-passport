const http = require('http');
const AuthenticationError = require('passport/lib/errors/authenticationerror');

class Framework {
  initialize() {

  }

  /**
   * Middleware that will authenticate a request using the given `strategy` name,
   * with optional `options` and `callback`.
   *
   * Examples:
   *
   *     passport.authenticate('local')(this.$context)
   *      .then(user => {
   *        // do somethings
   *      });
   *
   *     // Handle on 'GET /' in collection
   *     list() {
   *       passport.authenticate('basic', { session: false })(this.$context)
   *         .then(user => {
   *            // is auth
   *            // do somethings
   *         })
   *     }
   *
   * @param {Passport} passport
   * @param {String|Array.<String>} names
   * @param {Object} options
   * @return {Promise} promise
   */
  authenticate(passport, names, options = {}) {
    if (!Array.isArray(names)) {
      names = [names];
    }

    return async context => {
      // accumulator for failures from each strategy in the chain
      const failures = [];
      let data;

      for (const name of names) {
        data = await this.attempt(passport, name, context, options, failures);

        if (data && (data.status === 'success' || data.status === 'redirect')) {
          break;
        }
      }

      if (names.length === failures.length) {
        return this.allFailed(context, failures, options);
      }

      if (data.status === 'success') {
        return data;
      }

      if (data.status === 'redirect') {
        return data.status;
      }

      return undefined;
    };
  }

  /**
   * All failed handle
   *
   * @param context
   * @param failures
   * @param options
   * @returns {Object}
   */
  allFailed(context, failures, options) {
    const res = context.response;

    // Strategies are ordered by priority.  For the purpose of flashing a
    // message, the first failure will be displayed.
    let failure = failures[0] || {};
    let challenge = failure.challenge || {};
    let rstatus, status;

    // When failure handling is not delegated to the application, the default
    // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
    // header will be set according to the strategies in use (see
    // actions#fail).  If multiple strategies failed, each of their challenges
    // will be included in the response.
    const rchallenge = [];

    for (let j = 0, len = failures.length; j < len; j++) {
      failure = failures[j];
      challenge = failure.challenge;
      status = failure.status;

      rstatus = rstatus || status;
      if (typeof challenge === 'string') {
        rchallenge.push(challenge);
      }
    }

    res.setStatus(rstatus || 401);

    if (res.statusCode === 401 && rchallenge.length) {
      res.setHeader('WWW-Authenticate', rchallenge);
    }

    if (options.failWithError) {
      throw new AuthenticationError(http.STATUS_CODES[res.statusCode], rstatus);
    }

    const challenges = failures.map(fail => fail.challenge);
    const statuses = failures.map(fail => fail.status);

    return {challenges, statuses};
  }

  /**
   * Attempt
   * @param passport
   * @param layer
   * @param context
   * @param options
   * @param failures
   * @returns {Promise}
   */
  /* eslin max-params: 0 */
  attempt(passport, layer, context, options, failures) {
    // Get the strategy, which will be used as prototype from which to create
    // a new instance.  Action functions will then be bound to the strategy
    // within the context of the HTTP request/response pair.
    /* eslint no-underscore-dangle: 0 */
    const prototype = passport._strategy(layer);
    if (!prototype) {
      throw new Error(`Unknown authentication strategy "${layer}"`);
    }

    const strategy = Object.create(prototype);

    // ----- BEGIN STRATEGY AUGMENTATION -----
    // Augment the new strategy instance with action functions.  These action
    // functions are bound via closure the the request/response pair.  The end
    // goal of the strategy is to invoke *one* of these action methods, in
    // order to indicate successful or failed authentication, redirect to a
    // third-party identity provider, etc.

    const promise = new Promise((resolve, reject) => {

      /**
       * Authenticate `user`, with optional `info`.
       *
       * Strategies should call this function to successfully authenticate a
       * user.  `user` should be an object supplied by the application after it
       * has been given an opportunity to verify credentials.  `info` is an
       * optional argument containing additional user information.  This is
       * useful for third-party authentication strategies to pass profile
       * details.
       *
       * @param {Object} user
       * @param {Object} info
       * @api public
       */
      strategy.success = function(user, info = {}) {
        let property;

        if (passport) {
          property = passport._userProperty || 'user';
        }

        context.request[options.assignProperty || property] = user;

        if (options.authInfo !== false) {
          passport.transformAuthInfo(info, context.request, (err, tinfo) => {
            if (err) {
              return reject(err);
            }
            context.request.authInfo = tinfo;

            resolve({user, status: 'success'});
          });
        } else {
          resolve({user, status: 'success'});
        }
      };

      /**
       * Fail authentication, with optional `challenge` and `status`, defaulting
       * to 401.
       *
       * Strategies should call this function to fail an authentication attempt.
       *
       * @param {String} challenge
       * @param {Number} status
       * @api public
       */
      strategy.fail = (challenge, status) => {
        if (typeof challenge === 'number') {
          status = challenge;
          challenge = undefined;
        }

        // push this failure into the accumulator and attempt authentication
        // using the next strategy
        failures.push({challenge, status});
        resolve({status: 'fail'});
      };

      /**
       * Redirect to `url` with optional `status`, defaulting to 302.
       *
       * Strategies should call this function to redirect the user (via their
       * user agent) to a third-party website for authentication.
       *
       * @param {String} url
       * @param {Number} status
       * @api public
       */
      strategy.redirect = (url, status) => {
        context.redirect(url, status || 302);
        resolve({status: 'redirect'});
      };

      /**
       * Pass without making a success or fail decision.
       *
       * Under most circumstances, Strategies should not need to call this
       * function.  It exists primarily to allow previous authentication state
       * to be restored, for example from an HTTP session.
       *
       * @api public
       */
      strategy.pass = () => resolve({status: 'pass'});

      /**
       * Internal error while performing authentication.
       *
       * Strategies should call this function when an internal error occurs
       * during the process of performing authentication; for example, if the
       * user directory is not available.
       *
       * @param {Error} err
       * @api public
       */
      strategy.error = err => reject(err);

    });

    // ----- END STRATEGY AUGMENTATION -----

    strategy.authenticate(context.request, options);

    return promise;
  }
}

module.exports = Framework;
