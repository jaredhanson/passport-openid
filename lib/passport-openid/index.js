/**
 * Module dependencies.
 */
var Strategy = require('./strategy')
  , BadRequestError = require('./errors/badrequesterror')
  , InternalOpenIDError = require('./errors/internalopeniderror');


/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * Expose constructors.
 */
exports.Strategy = Strategy;

exports.BadRequestError = BadRequestError;
exports.InternalOpenIDError = InternalOpenIDError;
