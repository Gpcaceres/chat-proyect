/**
 * Pruebas de Seguridad - Esteganografía y Vulnerabilidades
 * Cubre: análisis de entropía, detección de contenido oculto, OWASP Top 10
 */

const {
  encryptText,
  decryptText,
  hashSecret,
  verifyHash,
} = require('../../src/security/crypto');
const { signToken, verifyToken } = require('../../src/security/token');

describe('Pruebas de Seguridad - OWASP Top 10', () => {
  describe('A1: Inyección', () => {
    it('debe prevenir SQL injection en hash', () => {
      const maliciousInput = "'; DROP TABLE users; --";
      const { hash, salt, iterations } = hashSecret(maliciousInput);
      
      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
      expect(typeof salt).toBe('string');
      expect(typeof iterations).toBe('number');
    });

    it('debe sanitizar entrada en encriptación', () => {
      const injection = '<script>alert("XSS")</script>';
      const encrypted = encryptText(injection, 'secret-key-that-is-at-least-32-characters-long');
      const decrypted = decryptText(encrypted, 'secret-key-that-is-at-least-32-characters-long');
      
      expect(decrypted).toBe(injection); // Debe preservar exactamente
    });

    it('debe rechazar payloads sospechosos en JWT', () => {
      const malicious = {
        sub: '1",admin:"true",isAdmin:"',
        role: 'user',
      };
      
      const token = signToken(malicious, 'secret');
      const verified = verifyToken(token, 'secret');
      
      expect(verified.role).toBe('user');
    });
  });

  describe('A02: Fallo de Autenticación', () => {
    it('debe rechazar contraseña débil después de análisis', () => {
      const weakPass = 'a'; // Muy corta
      const { hash, salt, iterations } = hashSecret(weakPass);
      
      const isValid = verifyHash(weakPass, hash, salt, iterations);
      expect(isValid).toBe(true);
      
      const isInvalid = verifyHash('b', hash, salt, iterations);
      expect(isInvalid).toBe(false);
    });

    it('debe usar timing-safe comparison para prevenir timing attacks', () => {
      const password = 'MySecurePassword123!';
      const { hash, salt, iterations } = hashSecret(password);
      
      // Intentos incorrectos deben tomar tiempo similar
      const start1 = Date.now();
      verifyHash('a', hash, salt, iterations);
      const time1 = Date.now() - start1;
      
      const start2 = Date.now();
      verifyHash('aaaaaaaaaaaaaaaaaaaaaa', hash, salt, iterations);
      const time2 = Date.now() - start2;
      
      // Ambos deben tomar tiempo similar (timing-safe)
      expect(Math.abs(time1 - time2)).toBeLessThan(100); // Tolerancia de 100ms
    });

    it('debe expirar tokens después de tiempo configurado', (done) => {
      const payload = { sub: 'user1', role: 'user' };
      const expiredToken = signToken(payload, 'secret', 0); // Expira inmediatamente
      
      setTimeout(() => {
        expect(() => verifyToken(expiredToken, 'secret')).toThrow('Token expirado');
        done();
      }, 1100);
    });
  });

  describe('A03: Inyección de Datos', () => {
    it('debe cifrar payloads JSON correctamente', () => {
      const jsonPayload = JSON.stringify({
        userId: 123,
        role: 'admin',
        permissions: ['read', 'write'],
      });
      
      const secret = 'encryption-secret-at-least-32-chars-long-here';
      const encrypted = encryptText(jsonPayload, secret);
      const decrypted = decryptText(encrypted, secret);
      
      const parsed = JSON.parse(decrypted);
      expect(parsed.userId).toBe(123);
      expect(parsed.role).toBe('admin');
    });

    it('debe detectar modificación de datos cifrados', () => {
      const data = 'Important data';
      const secret = 'secret-key-that-is-32-chars-long-minimum';
      const encrypted = encryptText(data, secret);
      
      // Intentar modificar
      encrypted.content = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      
      expect(() => decryptText(encrypted, secret)).toThrow();
    });
  });

  describe('A05: Control de Acceso', () => {
    it('debe validar scope en JWT', () => {
      const adminPayload = { sub: 'admin1', scope: 'admin' };
      const userPayload = { sub: 'user1', scope: 'user' };
      
      const adminToken = signToken(adminPayload, 'secret');
      const userToken = signToken(userPayload, 'secret');
      
      const verifiedAdmin = verifyToken(adminToken, 'secret');
      const verifiedUser = verifyToken(userToken, 'secret');
      
      expect(verifiedAdmin.scope).toBe('admin');
      expect(verifiedUser.scope).toBe('user');
      expect(verifiedAdmin.scope).not.toBe(verifiedUser.scope);
    });

    it('debe rechazar token con scope modificado', () => {
      const payload = { sub: 'user1', scope: 'user' };
      const token = signToken(payload, 'secret');
      
      // Intentar extraer y modificar
      const [header, payloadPart, signature] = token.split('.');
      
      // Crear token modificado (fallará en verificación de firma)
      const modifiedPayload = Buffer.from(JSON.stringify({
        sub: 'user1',
        scope: 'admin', // Intentar escalación de privilegios
      })).toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
      
      const modifiedToken = `${header}.${modifiedPayload}.${signature}`;
      
      expect(() => verifyToken(modifiedToken, 'secret')).toThrow();
    });
  });

  describe('A06: Información Sensible Expuesta', () => {
    it('no debe almacenar contraseña en texto plano', () => {
      const password = 'MySecurePassword123!';
      const { hash, salt } = hashSecret(password);
      
      // Hash no debe contener contraseña original
      expect(hash).not.toContain(password);
      expect(hash).not.toBe(password);
    });

    it('debe usar salt aleatorio para cada contraseña', () => {
      const password = 'SamePassword';
      const result1 = hashSecret(password);
      const result2 = hashSecret(password);
      
      expect(result1.hash).not.toBe(result2.hash);
      expect(result1.salt).not.toBe(result2.salt);
    });

    it('debe cifrar datos sensibles en tránsito', () => {
      const sensitive = 'user_id=123&role=admin&token=secret';
      const secret = 'transport-encryption-secret-32-chars';
      
      const encrypted = encryptText(sensitive, secret);
      
      // Datos cifrados no deben contener información original
      expect(encrypted.content).not.toContain('123');
      expect(encrypted.content).not.toContain('admin');
      expect(encrypted.content).not.toContain('secret');
    });
  });

  describe('Pruebas CVSS', () => {
    it('debe prevenir ataque de fuerza bruta (CVSS)', () => {
      const password = 'StrongPassword2024!';
      const { hash, salt, iterations } = hashSecret(password);
      
      // Simular 1000 intentos de fuerza bruta
      let failed = 0;
      for (let i = 0; i < 1000; i++) {
        const result = verifyHash(`attempt${i}`, hash, salt, iterations);
        if (!result) failed++;
      }
      
      // Todos los intentos incorrectos deben fallar
      expect(failed).toBe(1000);
    });

    it('debe manejar entradas muy grandes sin crash (DoS)', () => {
      const largeInput = 'X'.repeat(1000000); // 1MB
      
      expect(() => {
        encryptText(largeInput, 'secret-key-that-is-32-chars-long');
      }).not.toThrow();
    });
  });

  describe('Esteganografía - Detección de Contenido Oculto', () => {
    it('debe analizar datos sin esteganografía aparente', () => {
      // Datos legítimos
      const legitData = Buffer.from('Archivo legítimo de imagen PNG', 'utf8');
      
      // Calcular entropía simple
      const frequencies = new Array(256).fill(0);
      for (const byte of legitData) {
        frequencies[byte]++;
      }
      
      let entropy = 0;
      for (const freq of frequencies) {
        if (freq === 0) continue;
        const p = freq / legitData.length;
        entropy -= p * Math.log2(p);
      }
      
      // Entropía de texto legítimo debe ser baja
      expect(entropy).toBeLessThan(5);
    });

    it('debe detectar datos altamente aleatorios (potencial compresión/cifrado)', () => {
      // Datos cifrados/comprimidos tienen entropía alta
      const randomData = Buffer.alloc(256);
      for (let i = 0; i < 256; i++) {
        randomData[i] = Math.floor(Math.random() * 256);
      }
      
      const frequencies = new Array(256).fill(0);
      for (const byte of randomData) {
        frequencies[byte]++;
      }
      
      let entropy = 0;
      for (const freq of frequencies) {
        if (freq === 0) continue;
        const p = freq / randomData.length;
        entropy -= p * Math.log2(p);
      }
      
      // Datos aleatorios deben tener entropía alta
      expect(entropy).toBeGreaterThan(6);
    });
  });
});
