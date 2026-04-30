// ==================== JWT MANUAL (RFC 7519) ====================
const crypto = require('crypto');

/**
 * Codifica dato en base64url (RFC 7515)
 * Base64url es versión segura para URLs sin caracteres especiales
 * @param {*} data - Dato a codificar (se convierte a Buffer)
 * @returns {string} Base64url sin padding
 */
function base64UrlEncode(data) {
  // Convertir a base64 estándar
  return Buffer.from(data)
    .toString('base64')
    // Remover padding
    .replace(/=/g, '')
    // Reemplazar + → - (seguro para URLs)
    .replace(/\+/g, '-')
    // Reemplazar / → _ (seguro para URLs)
    .replace(/\//g, '_');
}

/**
 * Decodifica base64url a string UTF-8
 * @param {string} data - Base64url encoded data
 * @returns {string} Texto decodificado
 */
function base64UrlDecode(data) {
  // Invertir reemplazos: - → +, _ → /
  data = data.replace(/-/g, '+').replace(/_/g, '/');
  
  // Agregar padding si es necesario (4-n caracteres)
  const pad = 4 - (data.length % 4);
  if (pad !== 4) {
    data += '='.repeat(pad);
  }
  
  // Decodificar de base64
  return Buffer.from(data, 'base64').toString('utf8');
}

// ==================== GENERACIÓN DE JWT ====================
/**
 * Firma y genera JWT
 * Estructura: header.payload.signature (todos en base64url)
 * @param {object} payload - Datos a incluir en token
 * @param {string} secret - Secreto para firma HMAC-SHA256
 * @param {number} expiresInSeconds - Duración del token
 * @returns {string} JWT completo
 */
function signToken(payload, secret, expiresInSeconds = 3600) {
  // Header estándar JWT con algoritmo HS256
  const header = { alg: 'HS256', typ: 'JWT' };
  
  // Calcular tiempo de expiración (exp en segundos desde epoch)
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  
  // Agregar exp al payload (obligatorio para verificación)
  const fullPayload = { ...payload, exp };
  
  // Codificar header y payload en base64url
  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(fullPayload));
  
  // Contenido a firmar: header.payload
  const content = `${headerEncoded}.${payloadEncoded}`;
  
  // Firmar con HMAC-SHA256
  const signature = crypto
    .createHmac('sha256', secret)
    .update(content)
    .digest('base64')
    // Convertir a base64url
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  
  // Retornar JWT completo
  return `${content}.${signature}`;
}

// ==================== VERIFICACIÓN DE JWT ====================
/**
 * Verifica y decodifica JWT
 * @param {string} token - JWT a verificar
 * @param {string} secret - Secreto para verificar firma
 * @returns {object} Payload decodificado
 * @throws Error si token es inválido o expirado
 */
function verifyToken(token, secret) {
  // Dividir JWT en sus 3 partes
  const [header, payload, signature] = token.split('.');
  
  // Validar que tenga 3 partes
  if (!header || !payload || !signature) {
    throw new Error('Token inválido');
  }
  
  // Reconstruir contenido original (header.payload)
  const content = `${header}.${payload}`;
  
  // Calcular firma esperada
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(content)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  
  // Comparar firmas con timing-safe comparison
  // Previene ataques de timing que podrían predecir firma correcta
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
    throw new Error('Firma inválida');
  }
  
  // Decodificar payload
  const payloadDecoded = JSON.parse(base64UrlDecode(payload));
  
  // Verificar expiración
  if (payloadDecoded.exp && payloadDecoded.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expirado');
  }
  
  // Retornar payload si todo es válido
  return payloadDecoded;
}

module.exports = { signToken, verifyToken };
