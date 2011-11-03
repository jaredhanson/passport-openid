var vows = require('vows');
var assert = require('assert');
var util = require('util');
var OpenIDStrategy = require('passport-openid/strategy');


vows.describe('OpenIDStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function() {}
      );
    },
    
    'should be named session': function (strategy) {
      assert.equal(strategy.name, 'openid');
    },
  },
  
  'strategy handling an authorized request': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.verifyAssertion = function(url, callback) {
        callback(null, { authenticated: true, claimedIdentifier: 'http://www.example.com/profiles/username' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          req.user = user;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.query = {};
        req.query['openid.mode'] = 'id_res'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.identifier, 'http://www.example.com/profiles/username');
      },
    },
  },
  
  'strategy handling an authorized request that encounters an error while verifying assertion': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.verifyAssertion = function(url, callback) {
        callback(new Error('something went wrong'));
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid.mode'] = 'id_res'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling an authorized request that is not authenticated after verifying assertion': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.verifyAssertion = function(url, callback) {
        callback(null, { authenticated: false });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid.mode'] = 'id_res'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling an authorized request that is not validated': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, false);
        }
      );
      
      // mock
      strategy._relyingParty.verifyAssertion = function(url, callback) {
        callback(null, { authenticated: true, claimedIdentifier: 'http://www.example.com/profiles/username' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid.mode'] = 'id_res'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success' : function(err, req) {
        assert.isNull(err);
      },
      'should call fail' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling an authorized request that encounters an error during validation': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(new Error('something went wrong'));
        }
      );
      
      // mock
      strategy._relyingParty.verifyAssertion = function(url, callback) {
        callback(null, { authenticated: true, claimedIdentifier: 'http://www.example.com/profiles/username' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid.mode'] = 'id_res'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling an authentication canceled request': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid.mode'] = 'cancel'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success' : function(err, req) {
        assert.isNull(err);
      },
      'should call fail' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling a request to be redirected for authentication with identifier in body': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(null, 'http://provider.example.com/openid' + '#' + identifier);
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        req.body = {};
        req.body['openid_identifier'] = 'http://www.example.me/'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user OpenID provider URL' : function(err, req) {
        assert.equal(req.redirectURL, 'http://provider.example.com/openid#http://www.example.me/');
      },
    },
  },
  
  'strategy handling a request to be redirected for authentication with identifier in query': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(null, 'http://provider.example.com/openid' + '#' + identifier);
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['openid_identifier'] = 'http://www.example.me/'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user OpenID provider URL' : function(err, req) {
        assert.equal(req.redirectURL, 'http://provider.example.com/openid#http://www.example.me/');
      },
    },
  },
  
  'strategy handling a request to be redirected for authentication with identifier in body and identifierField option set': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          identifierField: 'identifier',
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(null, 'http://provider.example.com/openid' + '#' + identifier);
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        req.body = {};
        req.body['identifier'] = 'http://www.example.me/'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user OpenID provider URL' : function(err, req) {
        assert.equal(req.redirectURL, 'http://provider.example.com/openid#http://www.example.me/');
      },
    },
  },
  
  'strategy handling a request to be redirected with an undefined identifier': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(null, 'http://provider.example.com/openid');
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling a request to be redirected that encouters an error during discovery': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(new Error('something went wrong'));
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.body = {};
        req.body['openid_identifier'] = 'http://www.example.me/'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy handling a request to be redirected that does not find a provider during discovery': {
    topic: function() {
      var strategy = new OpenIDStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        },
        function(identifier, done) {
          done(null, { identifier: identifier });
        }
      );
      
      // mock
      strategy._relyingParty.authenticate = function(identifier, immediate, callback) {
        callback(null, null);
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.body = {};
        req.body['openid_identifier'] = 'http://www.example.me/'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
    },
  },
  
  'strategy constructed without a validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() {
        new OAuthStrategy({
          returnURL: 'https://www.example.com/auth/openid/return',
        });
      });
    },
  },

}).export(module);
