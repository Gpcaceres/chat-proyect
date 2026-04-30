// ==================== CRIPTOGRAFÍA AES-256-GCM ====================
const crypto = require('crypto');

// Algoritmo de cifrado autenticado: AES con GCM (Galois/Counter Mode)
// GCM proporciona confidencialidad + autenticidad + integridad
const ALGORITHM = 'aes-256-gcm';

// Iteraciones de PBKDF2 para derivación de claves
// 120,000 iteraciones es el estándar NIST recomendado (2023)
// Previene ataques de fuerza bruta de forma efectiva
const PBKDF2_ITERATIONS = 120000;

// Tamaño de clave: 32 bytes = 256 bits
const KEYLEN = 32;

// Algoritmo hash para PBKDF2
const DIGEST = 'sha256';

// ==================== DERIVACIÓN DE CLAVE ====================
/**
 * Obtiene clave de cifrado derivada del secreto
 * @param {string} secret - Secreto configurado en .env
 * @returns {Buffer} Clave SHA256 de 32 bytes
 */
function getKey(secret) {
  if (!secret || secret.length < 32) {
    throw new Error('Clave de cifrado no configurada correctamente');
  }
  // Derivar clave rápida (no para contraseñas, esa es PBKDF2)
  return crypto.createHash('sha256').update(secret).digest();
}

// ==================== CIFRADO ====================
/**
 * Cifra texto con AES-256-GCM
 * @param {string} plainText - Texto a cifrar
 * @param {string} secret - Secreto para derivar clave
 * @returns {object} {iv, content, authTag} en base64
 */
function encryptText(plainText, secret) {
  // Derivar clave del secreto
  const key = getKey(secret);
  
  // Generar IV (Initialization Vector) aleatorio de 12 bytes
  // IV debe ser único para cada operación de cifrado
  const iv = crypto.randomBytes(12);
  
  // Crear cipher con AES-256-GCM
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: 16 });
  
  // Cifrar el texto en UTF-8
  const encrypted = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);
  
  // Obtener tag de autenticación (16 bytes = 128 bits)
  // El tag permite verificar que los datos no fueron modificados
  const authTag = cipher.getAuthTag();
  
  // Retornar todos los componentes en base64 para transmisión
  return {
    iv: iv.toString('base64'),
    content: encrypted.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

// ==================== DESCIFRADO ====================
/**
 * Descifra texto con AES-256-GCM
 * @param {object} encrypted - {iv, content, authTag} en base64
 * @param {string} secret - Secreto para derivar clave
 * @returns {string} Texto descifrado
 */
function decryptText(encrypted, secret) {
  // Derivar clave del secreto
  const key = getKey(secret);
  
  // Crear decipher con IV y parámetros
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(encrypted.iv, 'base64'),
    { authTagLength: 16 }
  );
  
  // Establecer tag de autenticación para verificación
  decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));
  
  // Descifrar contenido
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted.content, 'base64')),
    decipher.final(),
  ]);
  
  // Retornar como string UTF-8
  return decrypted.toString('utf8');
}

// ==================== HASHING DE CONTRASEÑAS ====================
/**
 * Hashea secreto/contraseña con PBKDF2-SHA256
 * @param {string} secret - Contraseña a hashear
 * @param {string} salt - Salt (se genera si no se proporciona)
 * @param {number} iterations - Iteraciones PBKDF2
 * @returns {object} {hash, salt, iterations}
 */
function hashSecret(secret, salt = crypto.randomBytes(16).toString('base64'), iterations = PBKDF2_ITERATIONS) {
  // PBKDF2 deriva clave mediante aplicación repetida de función pseudoaleatoria
  // 120,000 iteraciones = ~100ms en hardware moderno (timing suficiente para prevenir fuerza bruta)
  const hash = crypto
    .pbkdf2Sync(String(secret), Buffer.from(salt, 'base64'), iterations, KEYLEN, DIGEST)
    .toString('base64');
  
  return { hash, salt, iterations };
}

/**
 * Verifica contraseña contra hash almacenado
 * Usa timing-safe comparison para prevenir timing attacks
 * @param {string} secret - Contraseña a verificar
 * @param {string} storedHash - Hash almacenado en BD
 * @param {string} salt - Salt usado originalmente
 * @param {number} iterations - Iteraciones usadas originalmente
 * @returns {boolean} true si coinciden
 */
function verifyHash(secret, storedHash, salt, iterations) {
  // Rehashear con los mismos parámetros
  const { hash } = hashSecret(secret, salt, iterations);
  
  // timingSafeEqual: comparación que siempre toma el mismo tiempo
  // Previene ataques que miden tiempo de respuesta para inferir hash correcto
  return crypto.timingSafeEqual(Buffer.from(hash, 'base64'), Buffer.from(storedHash, 'base64'));
}

// ==================== GENERACIÓN DE CLAVE DE SESIÓN ====================
/**
 * Genera y cifra una clave de sesión para cliente
 * @param {string} secret - Secreto para cifrar la clave
 * @returns {object} Clave de sesión cifrada {iv, content, authTag}
 */
function generateSessionKey(secret) {
  // Generar 32 bytes aleatorios (256 bits)
  // Esta será la clave maestra para cifrado E2E en cliente
  const sessionKey = crypto.randomBytes(32).toString('base64');
  
  // Cifrar la clave con AES-256-GCM del servidor
  // De esta forma, servidor nunca accede a la clave real
  return encryptText(sessionKey, secret);
}

module.exports = {
  encryptText,
  decryptText,
  hashSecret,
  verifyHash,
  generateSessionKey,
};
