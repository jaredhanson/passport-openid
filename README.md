# Passport-OpenID

[Passport](https://github.com/jaredhanson/passport) strategy for authenticating
with [OpenID](http://openid.net/).

This module lets you authenticate using OpenID in your Node.js applications.  By
plugging into Passport, OpenID authentication can be easily and unobtrusively
integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Installation

    $ npm install passport-openid

## Usage

#### Configure Strategy

The OpenID authentication strategy authenticates users using an OpenID
identifier.  The strategy requires a `validate` callback, which accepts this
identifier and calls `done` providing a user.  Additionally, options can be
supplied to specify a return URL and realm.

    passport.use(new OpenIDStrategy({
        returnURL: 'http://localhost:3000/auth/openid/return',
        realm: 'http://localhost:3000/'
      },
      function(identifier, done) {
        User.findByOpenID({ openId: identifier }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Using mixins with [node-openid](https://github.com/havard/node-openid/)

Exposure of the [node-openid](https://github.com/havard/node-openid/) module
is primarily intended to allow association state to be saved using different
storage mechanisms.

Extending the previous example:

    passport.use(new OpenIDStrategy({
        returnURL: 'http://localhost:3000/auth/openid/return',
        realm: 'http://localhost:3000/'
      },
      function(identifier, done) {
        User.findByOpenID(identifier, function (err, user) {
          done(err, user);
        });
      }
    ).addOpenIDMixins({
      saveAssociation: function(provider, type, handle, secret, expiry_time_in_seconds, callback) {
        // custom storage implementation
      },
      loadAssociation: function(handle, callback) {
        // custom storage retrieval implementation
      }
    }));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'openid'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/auth/openid',
      passport.authenticate('openid'),
      function(req, res){
        // The request will be redirected to the user's OpenID provider for
        // authentication, so this function will not be called.
      });

    app.get('/auth/openid/return', 
      passport.authenticate('openid', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples

For a complete, working example, refer to the [signon example](https://github.com/jaredhanson/passport-openid/tree/master/examples/signon).

## Strategies using OpenID

<table>
  <thead>
    <tr><th>Strategy</th></tr>
  </thead>
  <tbody>
    <tr><td><a href="https://github.com/jaredhanson/passport-google">Google</a></td></tr>
    <tr><td><a href="https://github.com/liamcurry/passport-steam">Steam</a></td></tr>
    <tr><td><a href="https://github.com/jaredhanson/passport-yahoo">Yahoo!</a></td></tr>
  </tbody>
</table>

## Tests

    $ npm install --dev
    $ make test

[![Build Status](https://secure.travis-ci.org/jaredhanson/passport-openid.png)](http://travis-ci.org/jaredhanson/passport-openid)

## Credits

  - [Jared Hanson](http://github.com/jaredhanson)

## License

(The MIT License)

Copyright (c) 2011 Jared Hanson

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
