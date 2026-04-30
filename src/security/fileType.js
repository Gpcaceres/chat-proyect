// ==================== DETECCIÓN DE TIPOS MIME CON MAGIC NUMBERS ====================
const fs = require('fs');

/**
 * Array de firmas conocidas de archivos (magic numbers)
 * Se usan para verificar tipo real de archivo vs extensión
 * Previene ataques como renombrar .zip como .png
 */
const MAGIC_NUMBERS = [
  {
    mime: 'image/png',
    ext: 'png',
    // PNG file signature
    signatures: ['89504e470d0a1a0a'],
  },
  {
    mime: 'image/jpeg',
    ext: 'jpg',
    // JPEG SOI (Start of Image) markers
    signatures: ['ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2', 'ffd8ffe3', 'ffd8ffe8'],
  },
  {
    mime: 'image/gif',
    ext: 'gif',
    // GIF 87a y 89a
    signatures: ['474946383761', '474946383961'],
  },
  {
    mime: 'application/pdf',
    ext: 'pdf',
    // PDF header
    signatures: ['25504446'],
  },
  {
    mime: 'application/zip',
    ext: 'zip',
    // ZIP file signatures
    signatures: ['504b0304', '504b0506', '504b0708'],
  },
  {
    mime: 'image/bmp',
    ext: 'bmp',
    // BMP header
    signatures: ['424d'],
  },
];

/**
 * Convierte buffer a hexadecimal
 * @param {Buffer} buffer - Datos a convertir
 * @param {number} length - Bytes a convertir
 * @returns {string} Representación hexadecimal
 */
function bufferToHex(buffer, length) {
  return buffer
    .subarray(0, length)
    .toString('hex')
    .toLowerCase();
}

/**
 * Comprueba si buffer comienza con firma específica
 * @param {Buffer} buffer - Datos del archivo
 * @param {string} signature - Firma en hexadecimal
 * @returns {boolean} true si coincide
 */
function matchesSignature(buffer, signature) {
  // Convertir hex a bytes (divide por 2)
  const neededLength = signature.length / 2;
  // Obtener hex de primeros N bytes
  const hex = bufferToHex(buffer, neededLength);
  // Comparar
  return hex.startsWith(signature.toLowerCase());
}

/**
 * Heurística para detectar archivos de texto plano
 * @param {Buffer} buffer - Primeros bytes del archivo
 * @returns {boolean} true si parece texto
 */
function looksLikeText(buffer) {
  // Analizar primeros 256 bytes
  const slice = buffer.subarray(0, 256);
  let printable = 0;
  
  // Contar caracteres imprimibles
  for (const byte of slice) {
    // Byte nulo = probablemente binario
    if (byte === 0) {
      return false;
    }
    // Tab, LF, CR, o rango ASCII imprimible (32-126)
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      printable += 1;
    }
  }
  
  // Si >90% es imprimible, probablemente sea texto
  return printable / (slice.length || 1) > 0.9;
}

/**
 * Detecta tipo MIME de archivo
 * 1. Compara con firmas conocidas
 * 2. Si no coincide, heurística de texto
 * 3. Retorna null si no se puede determinar
 * @param {string} filePath - Ruta del archivo
 * @returns {object|null} {mime, ext} o null
 */
function detectFileType(filePath) {
  // Leer archivo completo
  const buffer = fs.readFileSync(filePath);
  
  // Rechazar archivos vacíos
  if (!buffer.length) {
    return null;
  }

  // 1. Comparar contra firmas conocidas
  for (const entry of MAGIC_NUMBERS) {
    for (const signature of entry.signatures) {
      if (matchesSignature(buffer, signature)) {
        return { mime: entry.mime, ext: entry.ext };
      }
    }
  }

  // 2. Heurística de texto plano
  if (looksLikeText(buffer)) {
    return { mime: 'text/plain', ext: 'txt' };
  }

  // 3. No se pudo determinar
  return null;
}

module.exports = { detectFileType };
