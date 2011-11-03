/**
 * Module dependencies.
 */
var passport = require('passport')
  , openid = require('openid')
  , util = require('util')


function Strategy(options, validate) {
  if (!options.returnURL) throw new Error('OpenID authentication requires a returnURL option');
  if (!validate) throw new Error('OpenID authentication strategy requires a validate function');
  
  passport.Strategy.call(this);
  this.name = 'openid';
  this._validate = validate;
  
  this._relyingParty = new openid.RelyingParty(
    options.returnURL,
    options.realm,
    (options.stateless === undefined) ? false : options.stateless,
    (options.strict === undefined) ? false : options.strict,
    []); // extensions
      
  this._identifierField = options.identifierField || 'openid_identifier';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


Strategy.prototype.authenticate = function(req) {

  if (req.query && req.query['openid.mode']) {
    console.log('OpenID authentication response')
    console.log('  url: ' + req.url);
    console.log('  mode: ' + req.query['openid.mode']);
    
    // The request being authenticated contains an `openid.mode` parameter in
    // the query portion of the URL.  This indicates that the OpenID Provider
    // is responding to a prior authentication request with either a positive or
    // negative assertion.
    
    // NOTE: node-openid (0.3.1), which is used internally, will treat a cancel
    //       response as an error, setting `err` in the verifyAssertion
    //       callback.  However, for consistency with Passport semantics, a
    //       cancel response should be treated as an authentication failure,
    //       rather than an exceptional error.  As such, this condition is
    //       trapped and handled prior to being given to node-openid.
    
    if (req.query['openid.mode'] === 'cancel') { return this.fail(); }
    
    var self = this;
    this._relyingParty.verifyAssertion(req.url, function(err, result) {
      console.log('verifyAssertion callback');
      console.log('  err: ' + util.inspect(err));
      console.log('  result: ' + util.inspect(result));
      
      if (err) { return self.error(err); }
      if (!result.authenticated) { return self.error(new Error('OpenID authentication error')); }
      
      self._validate(result.claimedIdentifier, function(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(); }
        self.success(user);
      });
    });
    
  } else {
    // The request being authenticated is initiating OpenID authentication.  By
    // default, an `openid_identifier` parameter is expected as a parameter,
    // typically input by a user into a form.
  
    var identifier = undefined;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    }
    else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    }

    var self = this;
    this._relyingParty.authenticate(identifier, false, function(err, providerUrl) {
      console.log('authenticate callback');
      console.log('  err: ' + util.inspect(err));
      console.log('  url: ' + util.inspect(providerUrl));
      
      if (err || !providerUrl) { return self.error(err); }
      self.redirect(providerUrl);
    });
  }
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
