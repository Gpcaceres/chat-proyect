// ==================== TOTP (RFC 6238) - Autenticación de Dos Factores ====================
const crypto = require('crypto');

/**
 * Genera código TOTP (Time-based One-Time Password)
 * Basado en RFC 6238 - Estándar usado por Google Authenticator, Authy, etc.
 * @param {string} secret - Secreto compartido en base64
 * @param {number} window - Ventana de tolerancia: -1,0,+1 para sincronización de reloj
 * @returns {string} Código TOTP de 6 dígitos
 */
function generateTotp(secret, window = 0) {
  // TOTP divide tiempo en pasos de 30 segundos
  const timeStep = 30;
  
  // Calcular contador basado en tiempo actual
  const counter = Math.floor(Date.now() / 1000 / timeStep) + window;
  
  // Crear buffer de 8 bytes para almacenar contador
  const buffer = Buffer.alloc(8);
  // Big-endian encoding: primeros 4 bytes
  buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  // Últimos 4 bytes
  buffer.writeUInt32BE(counter & 0xffffffff, 4);
  
  // Decodificar secreto base64
  const key = Buffer.from(secret, 'base64');
  
  // HMAC-SHA1 del buffer
  const hmac = crypto.createHmac('sha1', key).update(buffer).digest();
  
  // Dinámico truncamiento: tomar último nibble como offset
  const offset = hmac[hmac.length - 1] & 0x0f;
  
  // Extraer 4 bytes a partir del offset, enmascarar bit de signo
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  
  // Retornar últimos 6 dígitos como string con padding
  return String(code % 1000000).padStart(6, '0');
}

/**
 * Verifica código TOTP ingresado por usuario
 * Tolera desviaciones de ±1 paso (±30 segundos) para sincronización de reloj
 * @param {string} token - Código de 6 dígitos ingresado
 * @param {string} secret - Secreto compartido en base64
 * @returns {boolean} true si código es válido
 */
function verifyTotp(token, secret) {
  // Si no hay secreto configurado, 2FA es opcional → retorna true
  if (!secret) {
    return true;
  }
  
  // Sanitizar entrada
  const sanitized = String(token || '').trim();
  
  // Validar que sea numérico
  if (!sanitized) {
    return false;
  }
  
  // Ventanas a validar: actual, -30s, +30s
  const windows = [0, -1, 1];
  
  try {
    // Generar TOTP para cada ventana y comparar
    // Permite sincronización de reloj desviada hasta ±30 segundos
    return windows.some((window) => generateTotp(secret, window) === sanitized);
  } catch (_error) {
    // Si hay error (secreto inválido, etc.), retornar false
    return false;
  }
}

module.exports = { verifyTotp };
