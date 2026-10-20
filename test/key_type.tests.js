var fs = require('fs');
var path = require('path');
var jws = require('jws');
var jwt = require('../index');
var expect = require('chai').expect;

function read(name) { return fs.readFileSync(path.join(__dirname, name), 'utf8'); }

var dsaPub = read('dsa-public.pem');
var ec256Priv = read('ec256-private.pem');
var ec256Pub = read('ec256-public.pem');
var ec384Pub = read('ec384-public.pem');
var rsaCert = read('rsa-cert.pem');
var rsaCertPriv = read('rsa-cert-private.pem');
// RS256 token whose signature was produced with the DSA private key matching
// dsa-public.pem (CVE-2022-23539: a legacy key type must not verify RS256)
var DSA_RS256_TOKEN = read('dsa-rs256.jwt').trim();

function expectInvalidSignature(done) {
  return function (err, decoded) {
    expect(err).to.be.an.instanceof(Error);
    expect(err.message).to.match(/invalid signature/);
    expect(decoded).to.be.undefined;
    done();
  };
}

describe('CVE-2022-23539: key type must match the algorithm', function () {
  it('fixture sanity: the DSA signature itself is valid for the DSA public key', function () {
    expect(jws.verify(DSA_RS256_TOKEN, dsaPub)).to.equal(true);
  });

  it('should not verify an RS256 token with a DSA public key', function (done) {
    jwt.verify(DSA_RS256_TOKEN, dsaPub, expectInvalidSignature(done));
  });

  it('should not verify an RS256 token with a DSA public key even when RS256 is allowed explicitly', function (done) {
    jwt.verify(DSA_RS256_TOKEN, dsaPub, { algorithms: ['RS256'] }, expectInvalidSignature(done));
  });

  it('should not verify an ES384 token with a P-256 key', function (done) {
    var token = jwt.sign({ foo: 'bar' }, ec256Priv, { algorithm: 'ES384' });
    expect(jws.verify(token, ec256Pub)).to.equal(true);
    jwt.verify(token, ec256Pub, expectInvalidSignature(done));
  });

  it('should not verify an ES256 token with a P-384 key', function (done) {
    var token = jwt.sign({ foo: 'bar' }, ec256Priv, { algorithm: 'ES256' });
    jwt.verify(token, ec384Pub, expectInvalidSignature(done));
  });

  it('should still verify an ES256 token with its P-256 key', function (done) {
    var token = jwt.sign({ foo: 'bar' }, ec256Priv, { algorithm: 'ES256' });
    jwt.verify(token, ec256Pub, function (err, decoded) {
      expect(err).to.be.null;
      expect(decoded.foo).to.equal('bar');
      done();
    });
  });

  it('should still verify an RS256 token with an X.509 certificate', function (done) {
    var token = jwt.sign({ foo: 'bar' }, rsaCertPriv, { algorithm: 'RS256' });
    jwt.verify(token, rsaCert, function (err, decoded) {
      expect(err).to.be.null;
      expect(decoded.foo).to.equal('bar');
      done();
    });
  });

  it('should not verify an RS256 token with an EC public key', function (done) {
    var token = jwt.sign({ foo: 'bar' }, rsaCertPriv, { algorithm: 'RS256' });
    jwt.verify(token, ec256Pub, expectInvalidSignature(done));
  });
});
