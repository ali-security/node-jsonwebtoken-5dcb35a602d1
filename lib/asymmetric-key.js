// CVE-2022-23539: classify a PEM key or certificate by the algorithm OID of its
// SubjectPublicKeyInfo / PrivateKeyInfo, i.e. what `KeyObject.asymmetricKeyType`
// reports on Node >= 11.6, which this package's Node 0.8/0.10 runtime lacks.
// Returns null for shared secrets and anything that is not parseable, so only
// a positively identified key type can reject an algorithm.
var OIDS = {
  '2a864886f70d010101': 'rsa',        // rsaEncryption
  '2a864886f70d01010a': 'rsa-pss',    // id-RSASSA-PSS
  '2a8648ce3d0201': 'ec',             // id-ecPublicKey
  '2a8648ce380401': 'dsa'             // id-dsa
};
var CURVES = {
  '2a8648ce3d030107': 'prime256v1',
  '2b81040022': 'secp384r1',
  '2b81040023': 'secp521r1'
};

function readTLV(buf, pos) {
  var tag = buf[pos], len = buf[pos + 1], start = pos + 2;
  if (len & 0x80) {
    var n = len & 0x7f; len = 0;
    for (var i = 0; i < n; i++) len = (len << 8) | buf[start + i];
    start += n;
  }
  return { tag: tag, start: start, end: start + len };
}

function children(buf, tlv) {
  var out = [], pos = tlv.start;
  while (pos < tlv.end) { var c = readTLV(buf, pos); out.push(c); pos = c.end; }
  return out;
}

function hex(buf, tlv) { return buf.slice(tlv.start, tlv.end).toString('hex'); }

function algInfo(buf, algId) {
  var parts = children(buf, algId);
  var info = { type: OIDS[hex(buf, parts[0])] || 'unknown' };
  if (info.type === 'ec' && parts[1] && parts[1].tag === 0x06) info.curve = CURVES[hex(buf, parts[1])] || 'unknown';
  return info;
}

function spkiInfo(buf, spki) { return algInfo(buf, children(buf, spki)[0]); }

module.exports = function asymmetricKeyInfo(key) {
  var pem = key == null ? '' : key.toString();
  var m = pem.match(/-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END /);
  if (!m) return null;
  var label = m[1];
  if (label === 'RSA PUBLIC KEY' || label === 'RSA PRIVATE KEY') return { type: 'rsa' };
  if (label === 'EC PRIVATE KEY') return { type: 'ec' };       // curve is inside the key; checked by crypto on verify
  if (label === 'DSA PRIVATE KEY') return { type: 'dsa' };
  try {
    var der = new Buffer(m[2].replace(/[^A-Za-z0-9+\/=]/g, ''), 'base64');
    var outer = readTLV(der, 0);
    if (label === 'PUBLIC KEY') return spkiInfo(der, outer);
    if (label === 'CERTIFICATE') {
      var tbs = children(der, outer)[0];
      var fields = children(der, tbs);
      return spkiInfo(der, fields[fields[0].tag === 0xa0 ? 6 : 5]);
    }
    if (label === 'PRIVATE KEY') return algInfo(der, children(der, outer)[1]);   // PKCS#8: version, AlgorithmIdentifier, key
  } catch (e) { /* fall through */ }
  return null;
};

var ALGS_FOR_KEY = { rsa: ['RS256', 'RS384', 'RS512'], ec: ['ES256', 'ES384', 'ES512'] };
var CURVE_FOR_ALG = { ES256: 'prime256v1', ES384: 'secp384r1', ES512: 'secp521r1' };

module.exports.keyAllowsAlgorithm = function keyAllowsAlgorithm(info, alg) {
  var allowed = ALGS_FOR_KEY[info.type];
  if (!allowed || allowed.indexOf(alg) === -1) return false;
  if (info.curve && info.curve !== CURVE_FOR_ALG[alg]) return false;
  return true;
};
