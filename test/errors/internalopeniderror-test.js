var vows = require('vows');
var assert = require('assert');
var util = require('util');
var InternalOpenIDError = require('passport-openid/errors/internalopeniderror');


vows.describe('InternalOpenIDError').addBatch({
  
  'when constructed with only a message': {
    topic: function() {
      return new InternalOpenIDError('oops');
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops');
    },
  },
  
  'when constructed with a message and error': {
    topic: function() {
      return new InternalOpenIDError('oops', new Error('something is wrong'));
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops (Error: something is wrong)');
    },
  },
  
  'when constructed with a message and object with message': {
    topic: function() {
      return new InternalOpenIDError('oops', { message: 'invalid OpenID provider' });
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops (message: invalid OpenID provider)');
    },
  },
  
}).export(module);
