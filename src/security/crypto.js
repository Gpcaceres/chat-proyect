const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 120000;
const KEYLEN = 32;
const DIGEST = 'sha256';

function getKey(secret) {
  if (!secret || secret.length < 32) {
    throw new Error('Clave de cifrado no configurada correctamente');
  }
  return crypto.createHash('sha256').update(secret).digest();
}

function encryptText(plainText, secret) {
  const key = getKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: 16 });
  const encrypted = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    content: encrypted.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

function decryptText(encrypted, secret) {
  const key = getKey(secret);
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(encrypted.iv, 'base64'),
    { authTagLength: 16 }
  );
  decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted.content, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

function hashSecret(secret, salt = crypto.randomBytes(16).toString('base64'), iterations = PBKDF2_ITERATIONS) {
  const hash = crypto
    .pbkdf2Sync(String(secret), Buffer.from(salt, 'base64'), iterations, KEYLEN, DIGEST)
    .toString('base64');
  return { hash, salt, iterations };
}

function verifyHash(secret, storedHash, salt, iterations) {
  const { hash } = hashSecret(secret, salt, iterations);
  return crypto.timingSafeEqual(Buffer.from(hash, 'base64'), Buffer.from(storedHash, 'base64'));
}

function generateSessionKey(secret) {
  return encryptText(crypto.randomBytes(32).toString('base64'), secret);
}

module.exports = {
  encryptText,
  decryptText,
  hashSecret,
  verifyHash,
  generateSessionKey,
};
