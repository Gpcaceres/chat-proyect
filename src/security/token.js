const crypto = require('crypto');

function base64UrlEncode(data) {
  return Buffer.from(data)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(data) {
  data = data.replace(/-/g, '+').replace(/_/g, '/');
  const pad = 4 - (data.length % 4);
  if (pad !== 4) {
    data += '='.repeat(pad);
  }
  return Buffer.from(data, 'base64').toString('utf8');
}

function signToken(payload, secret, expiresInSeconds = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const fullPayload = { ...payload, exp };
  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(fullPayload));
  const content = `${headerEncoded}.${payloadEncoded}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(content)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${content}.${signature}`;
}

function verifyToken(token, secret) {
  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) {
    throw new Error('Token inválido');
  }
  const content = `${header}.${payload}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(content)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
    throw new Error('Firma inválida');
  }
  const payloadDecoded = JSON.parse(base64UrlDecode(payload));
  if (payloadDecoded.exp && payloadDecoded.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expirado');
  }
  return payloadDecoded;
}

module.exports = { signToken, verifyToken };
