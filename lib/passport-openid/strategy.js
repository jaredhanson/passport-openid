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
  
  var extensions = [];
  if (options.profile) {
    var sreg = new openid.SimpleRegistration({
      "fullname" : true,
      "nickname" : true, 
      "email" : true, 
      "dob" : true, 
      "gender" : true, 
      "postcode" : true,
      "country" : true, 
      "timezone" : true,
      "language" : true
    });
    extensions.push(sreg);
  }
  if (options.profile) {
    var ax = new openid.AttributeExchange({
      "http://axschema.org/namePerson/first": "required",
      "http://axschema.org/namePerson/last": "required",
      "http://axschema.org/contact/email": "required"
    });
    extensions.push(ax);
  }
  
  this._relyingParty = new openid.RelyingParty(
    options.returnURL,
    options.realm,
    (options.stateless === undefined) ? false : options.stateless,
    (options.secure === undefined) ? true : options.secure,
    extensions);
      
  this._providerURL = options.providerURL;
  this._identifierField = options.identifierField || 'openid_identifier';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


Strategy.prototype.authenticate = function(req) {

  if (req.query && req.query['openid.mode']) {
    // The request being authenticated contains an `openid.mode` parameter in
    // the query portion of the URL.  This indicates that the OpenID Provider
    // is responding to a prior authentication request with either a positive or
    // negative assertion.  If a positive assertion is received, it will be
    // verified according to the rules outlined in the OpenID 2.0 specification.
    
    // NOTE: node-openid (0.3.1), which is used internally, will treat a cancel
    //       response as an error, setting `err` in the verifyAssertion
    //       callback.  However, for consistency with Passport semantics, a
    //       cancel response should be treated as an authentication failure,
    //       rather than an exceptional error.  As such, this condition is
    //       trapped and handled prior to being given to node-openid.
    
    if (req.query['openid.mode'] === 'cancel') { return this.fail(); }
    
    var self = this;
    this._relyingParty.verifyAssertion(req.url, function(err, result) {
      if (err) { return self.error(err); }
      if (!result.authenticated) { return self.error(new Error('OpenID authentication error')); }
      
      var profile = self._parseProfileExt(result);
      
      function validated(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(); }
        self.success(user);
      }
      
      var arity = self._validate.length;
      if (arity == 3) {
        self._validate(result.claimedIdentifier, profile, validated);
      } else {
        self._validate(result.claimedIdentifier, validated);
      }
    });
  } else {
    // The request being authenticated is initiating OpenID authentication.  By
    // default, an `openid_identifier` parameter is expected as a parameter,
    // typically input by a user into a form.
    //
    // During the process of initiating OpenID authentication, discovery will be
    // performed to determine the endpoints used to authenticate with the user's
    // OpenID provider.  Optionally, and by default, an association will be
    // established with the OpenID provider which is used to verify subsequent
    // protocol messages and reduce round trips.
  
    var identifier = undefined;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    }
    
    if (!identifier) { return this.error(new Error('OpenID identifier undefined')); }

    var self = this;
    this._relyingParty.authenticate(identifier, false, function(err, providerUrl) {
      if (err || !providerUrl) { return self.error(err); }
      self.redirect(providerUrl);
    });
  }
}

Strategy.prototype._parseProfileExt = function(params) {
  var profile = {};
  
  // parse simple registration parameters
  profile.displayName = params['fullname'];
  profile.emails = [{ value: params['email'] }];
  
  // parse attribute exchange parameters
  profile.name = { familyName: params['lastname'],
                   givenName: params['firstname'] };
  if (!profile.displayName) {
    profile.displayName = params['firstname'] + ' ' + params['lastname'];
  }
  if (!profile.emails) {
    profile.emails = [{ value: params['email'] }];
  }
  
  return profile;
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
