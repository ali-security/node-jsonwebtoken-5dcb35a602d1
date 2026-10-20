var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var jwt = require('../index');
var expect = require('chai').expect;


var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

function base64url(obj) {
  return new Buffer(JSON.stringify(obj)).toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function expectInvalidSignature(done) {
  return function (err, decoded) {
    expect(err).to.be.an.instanceof(Error);
    expect(err.message).to.match(/invalid signature/);
    expect(decoded).to.be.undefined;
    done();
  };
}

describe('signing with pub key as symmetric', function () {
  it('should not verify', function (done) {
    jwt.verify(TOKEN, pub, expectInvalidSignature(done));
  });

  it('should not verify a HS256 token signed with the certificate string', function (done) {
    var token = jwt.sign({ foo: 'bar' }, pub, { algorithm: 'HS256' });
    jwt.verify(token, pub, expectInvalidSignature(done));
  });

  it('should not verify a HS256 token signed with the certificate buffer', function (done) {
    var pubBuffer = fs.readFileSync(path.join(__dirname, 'pub.pem'));
    var token = jwt.sign({ foo: 'bar' }, pubBuffer, { algorithm: 'HS256' });
    jwt.verify(token, pubBuffer, expectInvalidSignature(done));
  });

  it('should not verify a HS512 token signed with a BEGIN PUBLIC KEY key', function (done) {
    var rsaPub = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));
    var token = jwt.sign({ foo: 'bar' }, rsaPub, { algorithm: 'HS512' });
    jwt.verify(token, rsaPub, expectInvalidSignature(done));
  });

  it('should not verify a HS256 token signed with a BEGIN RSA PUBLIC KEY key', function (done) {
    var rsaPubKey = fs.readFileSync(path.join(__dirname, 'rsa-public-key.pem'));
    var token = jwt.sign({ foo: 'bar' }, rsaPubKey, { algorithm: 'HS256' });
    jwt.verify(token, rsaPubKey, expectInvalidSignature(done));
  });

  it('should not verify a lowercase hs256 token signed with the certificate', function (done) {
    var input = base64url({ typ: 'JWT', alg: 'hs256' }) + '.' + base64url({ foo: 'bar' });
    var signature = crypto.createHmac('sha256', pub).update(input).digest('base64')
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    jwt.verify(input + '.' + signature, pub, expectInvalidSignature(done));
  });
});

describe('unsigned token with alg none', function () {
  var token = base64url({ typ: 'JWT', alg: 'none' }) + '.' +
              base64url({ foo: 'bar' }) + '.';

  it('should not verify with a public key', function (done) {
    jwt.verify(token, pub, expectInvalidSignature(done));
  });

  it('should not verify with a secret', function (done) {
    jwt.verify(token, 'shhhhhh', expectInvalidSignature(done));
  });
});

describe('when options.algorithms is provided', function () {
  it('should not verify a token whose alg is not listed', function (done) {
    var token = jwt.sign({ foo: 'bar' }, pub, { algorithm: 'HS256' });
    jwt.verify(token, pub, { algorithms: ['RS256'] }, expectInvalidSignature(done));
  });

  it('should verify a token whose alg is listed', function (done) {
    var token = jwt.sign({ foo: 'bar' }, 'shhhhhh', { algorithm: 'HS384' });
    jwt.verify(token, 'shhhhhh', { algorithms: ['HS384'] }, function (err, decoded) {
      expect(err).to.not.exist;
      expect(decoded.foo).to.equal('bar');
      done();
    });
  });
});
