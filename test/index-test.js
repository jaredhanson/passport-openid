var vows = require('vows');
var assert = require('assert');
var util = require('util');
var openid = require('passport-openid');


vows.describe('passport-openid').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(openid.version);
    },
  },
  
}).export(module);
