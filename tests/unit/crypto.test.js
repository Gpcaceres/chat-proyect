/**
 * Pruebas unitarias para módulo de criptografía
 * Cubre: cifrado AES-256-GCM, PBKDF2, hashing
 */

const crypto = require('crypto');
const {
  encryptText,
  decryptText,
  hashSecret,
  verifyHash,
  generateSessionKey,
} = require('../../src/security/crypto');

describe('Módulo Crypto - AES-256-GCM', () => {
  const testSecret = 'test-secret-key-that-is-long-enough-32-chars';
  const plainText = 'Mensaje de prueba';

  describe('encryptText', () => {
    it('debe cifrar texto y retornar objeto con iv, content, authTag', () => {
      const encrypted = encryptText(plainText, testSecret);
      
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('content');
      expect(encrypted).toHaveProperty('authTag');
      expect(typeof encrypted.iv).toBe('string');
      expect(typeof encrypted.content).toBe('string');
      expect(typeof encrypted.authTag).toBe('string');
    });

    it('debe generar IV diferente para cada cifrado', () => {
      const enc1 = encryptText(plainText, testSecret);
      const enc2 = encryptText(plainText, testSecret);
      
      expect(enc1.iv).not.toBe(enc2.iv);
      expect(enc1.content).not.toBe(enc2.content);
    });

    it('debe manejar textos vacíos', () => {
      const encrypted = encryptText('', testSecret);
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('content');
    });

    it('debe convertir entrada no-string a string', () => {
      const encrypted = encryptText(12345, testSecret);
      expect(encrypted).toHaveProperty('content');
    });
  });

  describe('decryptText', () => {
    it('debe descifrar texto cifrado correctamente', () => {
      const encrypted = encryptText(plainText, testSecret);
      const decrypted = decryptText(encrypted, testSecret);
      
      expect(decrypted).toBe(plainText);
    });

    it('debe lanzar error si el tag de autenticación es inválido', () => {
      const encrypted = encryptText(plainText, testSecret);
      // Modificar tag
      encrypted.authTag = 'AAAAAAAAAAAAAAAA';
      
      expect(() => decryptText(encrypted, testSecret)).toThrow();
    });

    it('debe lanzar error si el contenido está corrupto', () => {
      const encrypted = encryptText(plainText, testSecret);
      // Modificar contenido
      encrypted.content = 'AAAAAAAAAAAAAAAA';
      
      expect(() => decryptText(encrypted, testSecret)).toThrow();
    });

    it('debe lanzar error con secreto incorrecto', () => {
      const encrypted = encryptText(plainText, testSecret);
      
      expect(() => decryptText(encrypted, 'wrong-secret-key-that-is-32-chars-long')).toThrow();
    });
  });

  describe('hashSecret - PBKDF2', () => {
    it('debe generar hash con salt aleatorio', () => {
      const result = hashSecret('password123');
      
      expect(result).toHaveProperty('hash');
      expect(result).toHaveProperty('salt');
      expect(result).toHaveProperty('iterations');
      expect(result.iterations).toBe(120000);
    });

    it('debe usar salt proporcionado', () => {
      const salt = crypto.randomBytes(16).toString('base64');
      const result = hashSecret('password123', salt, 120000);
      
      expect(result.salt).toBe(salt);
    });

    it('dos hashes del mismo password con distinto salt deben ser diferentes', () => {
      const hash1 = hashSecret('password123');
      const hash2 = hashSecret('password123');
      
      expect(hash1.hash).not.toBe(hash2.hash);
      expect(hash1.salt).not.toBe(hash2.salt);
    });

    it('debe generar hash reproducible con mismo salt', () => {
      const salt = crypto.randomBytes(16).toString('base64');
      const hash1 = hashSecret('password123', salt, 120000);
      const hash2 = hashSecret('password123', salt, 120000);
      
      expect(hash1.hash).toBe(hash2.hash);
    });
  });

  describe('verifyHash - Verificación timing-safe', () => {
    it('debe verificar contraseña correcta', () => {
      const password = 'MySecurePassword123!';
      const { hash, salt, iterations } = hashSecret(password);
      
      const isValid = verifyHash(password, hash, salt, iterations);
      expect(isValid).toBe(true);
    });

    it('debe rechazar contraseña incorrecta', () => {
      const password = 'MySecurePassword123!';
      const { hash, salt, iterations } = hashSecret(password);
      
      const isValid = verifyHash('WrongPassword', hash, salt, iterations);
      expect(isValid).toBe(false);
    });

    it('debe ser sensible a cambios mínimos en contraseña', () => {
      const password = 'password';
      const { hash, salt, iterations } = hashSecret(password);
      
      const isValid = verifyHash('passwor', hash, salt, iterations);
      expect(isValid).toBe(false);
    });
  });

  describe('generateSessionKey', () => {
    it('debe generar clave de sesión cifrada', () => {
      const sessionKey = generateSessionKey(testSecret);
      
      expect(sessionKey).toHaveProperty('iv');
      expect(sessionKey).toHaveProperty('content');
      expect(sessionKey).toHaveProperty('authTag');
    });

    it('debe generar diferentes claves en cada llamada', () => {
      const key1 = generateSessionKey(testSecret);
      const key2 = generateSessionKey(testSecret);
      
      expect(key1.iv).not.toBe(key2.iv);
      expect(key1.content).not.toBe(key2.content);
    });

    it('debe poder descifrarse correctamente', () => {
      const sessionKey = generateSessionKey(testSecret);
      const decrypted = decryptText(sessionKey, testSecret);
      
      // Debe ser base64 válido (32 bytes)
      const buffer = Buffer.from(decrypted, 'base64');
      expect(buffer.length).toBe(32);
    });
  });

  describe('Integración: Ciclo completo cifrado-descifrado', () => {
    it('debe cifrar y descifrar múltiples mensajes secuencialmente', () => {
      const messages = [
        'Primer mensaje',
        'Segundo mensaje con números 123',
        'Tercer mensaje con caracteres especiales: @#$%^&*()',
      ];

      messages.forEach((msg) => {
        const encrypted = encryptText(msg, testSecret);
        const decrypted = decryptText(encrypted, testSecret);
        expect(decrypted).toBe(msg);
      });
    });

    it('debe mantener integridad con payloads grandes', () => {
      const largeText = 'X'.repeat(10000);
      const encrypted = encryptText(largeText, testSecret);
      const decrypted = decryptText(encrypted, testSecret);
      
      expect(decrypted).toBe(largeText);
      expect(decrypted.length).toBe(10000);
    });
  });
});
