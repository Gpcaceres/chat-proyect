const crypto = require('crypto');

function generateTotp(secret, window = 0) {
  const timeStep = 30;
  const counter = Math.floor(Date.now() / 1000 / timeStep) + window;
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buffer.writeUInt32BE(counter & 0xffffffff, 4);
  const key = Buffer.from(secret, 'base64');
  const hmac = crypto.createHmac('sha1', key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function verifyTotp(token, secret) {
  if (!secret) {
    return true;
  }
  const sanitized = String(token || '').trim();
  if (!sanitized) {
    return false;
  }
  const windows = [0, -1, 1];
  try {
    return windows.some((window) => generateTotp(secret, window) === sanitized);
  } catch (_error) {
    return false;
  }
}

module.exports = { verifyTotp };
