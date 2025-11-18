/**
 * Pruebas unitarias para módulo de tokens JWT
 * Cubre: generación, verificación, expiración
 */

const { signToken, verifyToken } = require('../../src/security/token');

describe('Módulo Token - JWT HMAC-SHA256', () => {
  const secret = 'test-secret-key-for-jwt-testing';
  const payload = {
    sub: 'user123',
    username: 'testuser',
    scope: 'user',
  };

  describe('signToken', () => {
    it('debe generar JWT válido', () => {
      const token = signToken(payload, secret);
      
      expect(typeof token).toBe('string');
      const parts = token.split('.');
      expect(parts.length).toBe(3);
    });

    it('debe incluir expiración en el payload', () => {
      const token = signToken(payload, secret, 3600);
      const [, payloadPart] = token.split('.');
      
      // Decodificar payload
      const decoded = JSON.parse(
        Buffer.from(payloadPart.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()
      );
      
      expect(decoded).toHaveProperty('exp');
      expect(typeof decoded.exp).toBe('number');
    });

    it('debe incluir todos los campos del payload original', () => {
      const token = signToken(payload, secret);
      const verified = verifyToken(token, secret);
      
      expect(verified.sub).toBe(payload.sub);
      expect(verified.username).toBe(payload.username);
      expect(verified.scope).toBe(payload.scope);
    });

    it('debe generar firmas diferentes con secretos diferentes', () => {
      const token1 = signToken(payload, secret);
      const token2 = signToken(payload, 'different-secret-key-for-testing');
      
      expect(token1).not.toBe(token2);
    });

    it('debe usar expiración por defecto de 3600 segundos', () => {
      const beforeTime = Math.floor(Date.now() / 1000);
      const token = signToken(payload, secret);
      const afterTime = Math.floor(Date.now() / 1000);
      
      const verified = verifyToken(token, secret);
      
      // Verificar que exp está entre now+3600 y now+3601
      expect(verified.exp).toBeGreaterThanOrEqual(beforeTime + 3600);
      expect(verified.exp).toBeLessThanOrEqual(afterTime + 3601);
    });
  });

  describe('verifyToken', () => {
    it('debe verificar token válido', () => {
      const token = signToken(payload, secret);
      
      expect(() => verifyToken(token, secret)).not.toThrow();
    });

    it('debe retornar payload verificado', () => {
      const token = signToken(payload, secret);
      const verified = verifyToken(token, secret);
      
      expect(verified).toHaveProperty('exp');
      expect(verified.sub).toBe(payload.sub);
    });

    it('debe lanzar error con token inválido', () => {
      // Token con formato incorrecto pero con 3 partes
      const invalidToken = 'header.payload.signature';
      
      expect(() => verifyToken(invalidToken, secret)).toThrow();
    });

    it('debe lanzar error con token incompleto', () => {
      expect(() => verifyToken('only.two', secret)).toThrow('Token inválido');
    });

    it('debe lanzar error si firma es incorrecta', () => {
      const token = signToken(payload, secret);
      const [header, payloadPart] = token.split('.');
      // Firma diferente del mismo tamaño
      const invalidSignature = 'A'.repeat(88); // Mismo tamaño que firma válida
      const invalidToken = `${header}.${payloadPart}.${invalidSignature}`;
      
      expect(() => verifyToken(invalidToken, secret)).toThrow();
    });

    it('debe lanzar error con secreto incorrecto', () => {
      const token = signToken(payload, secret);
      
      expect(() => verifyToken(token, 'wrong-secret')).toThrow('Firma inválida');
    });

    it('debe lanzar error si token está expirado', (done) => {
      // Crear token con expiración inmediata
      const expiredToken = signToken(payload, secret, 0);
      
      // Esperar 1 segundo para asegurar expiración
      setTimeout(() => {
        expect(() => verifyToken(expiredToken, secret)).toThrow('Token expirado');
        done();
      }, 1100);
    });

    it('debe rechazar tokens con payload modificado', () => {
      let token = signToken(payload, secret);
      
      // Intentar modificar payload
      const parts = token.split('.');
      // Modificar un carácter en el payload
      const modifiedPayload = parts[1].slice(0, -1) + 'X';
      const modifiedToken = `${parts[0]}.${modifiedPayload}.${parts[2]}`;
      
      expect(() => verifyToken(modifiedToken, secret)).toThrow();
    });
  });

  describe('Ciclo completo: sign -> verify', () => {
    it('debe verificar token generado correctamente', () => {
      const customPayload = {
        sub: 'admin456',
        username: 'administrator',
        scope: 'admin',
        permissions: ['read', 'write', 'delete'],
      };
      
      const token = signToken(customPayload, secret, 7200);
      const verified = verifyToken(token, secret);
      
      expect(verified.sub).toBe(customPayload.sub);
      expect(verified.username).toBe(customPayload.username);
      expect(verified.permissions).toEqual(customPayload.permissions);
    });

    it('debe funcionar con diferentes tiempos de expiración', () => {
      const times = [300, 3600, 86400]; // 5min, 1h, 1day
      
      times.forEach((expiresIn) => {
        const token = signToken(payload, secret, expiresIn);
        const verified = verifyToken(token, secret);
        
        const now = Math.floor(Date.now() / 1000);
        expect(verified.exp).toBeGreaterThanOrEqual(now + expiresIn - 1);
        expect(verified.exp).toBeLessThanOrEqual(now + expiresIn + 1);
      });
    });
  });
});
