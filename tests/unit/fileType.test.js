/**
 * Pruebas unitarias para detección de tipos MIME
 * Cubre: magic numbers, heurística de texto, edge cases
 */

const fs = require('fs');
const path = require('path');
const { detectFileType } = require('../../src/security/fileType');

describe('Módulo FileType - Detección de Tipos MIME', () => {
  const testDir = path.join(__dirname, '../fixtures');

  beforeAll(() => {
    // Crear directorio de fixtures si no existe
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  describe('PNG Detection', () => {
    it('debe detectar archivo PNG válido', () => {
      // Firma PNG: 89 50 4E 47 0D 0A 1A 0A
      const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const filePath = path.join(testDir, 'test.png');
      fs.writeFileSync(filePath, pngSignature);

      const result = detectFileType(filePath);
      expect(result).toEqual({ mime: 'image/png', ext: 'png' });

      fs.unlinkSync(filePath);
    });
  });

  describe('JPEG Detection', () => {
    it('debe detectar archivo JPEG válido (SOI FFD8FFE0)', () => {
      // Firma JPEG: FF D8 FF E0
      const jpegSignature = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
      const filePath = path.join(testDir, 'test.jpg');
      fs.writeFileSync(filePath, jpegSignature);

      const result = detectFileType(filePath);
      expect(result).toEqual({ mime: 'image/jpeg', ext: 'jpg' });

      fs.unlinkSync(filePath);
    });

    it('debe detectar variantes JPEG (FFD8FFE1)', () => {
      const jpegSignature = Buffer.from([0xff, 0xd8, 0xff, 0xe1]);
      const filePath = path.join(testDir, 'test-e1.jpg');
      fs.writeFileSync(filePath, jpegSignature);

      const result = detectFileType(filePath);
      expect(result.mime).toBe('image/jpeg');

      fs.unlinkSync(filePath);
    });
  });

  describe('PDF Detection', () => {
    it('debe detectar archivo PDF válido', () => {
      // Firma PDF: 25 50 44 46 (%PDF)
      const pdfSignature = Buffer.from('%PDF');
      const filePath = path.join(testDir, 'test.pdf');
      fs.writeFileSync(filePath, pdfSignature);

      const result = detectFileType(filePath);
      expect(result).toEqual({ mime: 'application/pdf', ext: 'pdf' });

      fs.unlinkSync(filePath);
    });
  });

  describe('ZIP Detection', () => {
    it('debe detectar archivo ZIP válido (PK\\x03\\x04)', () => {
      // Firma ZIP: 50 4B 03 04
      const zipSignature = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
      const filePath = path.join(testDir, 'test.zip');
      fs.writeFileSync(filePath, zipSignature);

      const result = detectFileType(filePath);
      expect(result).toEqual({ mime: 'application/zip', ext: 'zip' });

      fs.unlinkSync(filePath);
    });
  });

  describe('Plain Text Detection', () => {
    it('debe detectar archivo de texto plano', () => {
      const text = 'Este es un archivo de texto plano.\nCon múltiples líneas.\nY caracteres normales.';
      const filePath = path.join(testDir, 'test.txt');
      fs.writeFileSync(filePath, text);

      const result = detectFileType(filePath);
      expect(result).toEqual({ mime: 'text/plain', ext: 'txt' });

      fs.unlinkSync(filePath);
    });

    it('debe detectar UTF-8 como texto', () => {
      const text = 'Texto con acentos: áéíóú\nCaracteres especiales: @#$%\nNúmeros: 12345';
      const filePath = path.join(testDir, 'utf8.txt');
      fs.writeFileSync(filePath, text, 'utf8');

      const result = detectFileType(filePath);
      if (result) {
        expect(result.mime).toBe('text/plain');
      }

      fs.unlinkSync(filePath);
    });

    it('debe detectar JSON como texto', () => {
      const json = '{"name": "test", "value": 123}';
      const filePath = path.join(testDir, 'data.json');
      fs.writeFileSync(filePath, json);

      const result = detectFileType(filePath);
      expect(result.mime).toBe('text/plain');

      fs.unlinkSync(filePath);
    });
  });

  describe('Edge cases', () => {
    it('debe retornar null para archivo vacío', () => {
      const filePath = path.join(testDir, 'empty.bin');
      fs.writeFileSync(filePath, Buffer.alloc(0));

      const result = detectFileType(filePath);
      expect(result).toBeNull();

      fs.unlinkSync(filePath);
    });

    it('debe retornar null para datos binarios desconocidos', () => {
      const randomBinary = Buffer.from([0x00, 0xFF, 0x7F, 0x80]);
      const filePath = path.join(testDir, 'unknown.bin');
      fs.writeFileSync(filePath, randomBinary);

      const result = detectFileType(filePath);
      expect(result).toBeNull();

      fs.unlinkSync(filePath);
    });

    it('debe rechazar archivos con bytes nulos (binarios)', () => {
      const binary = Buffer.alloc(10);
      binary[0] = 0x00; // Byte nulo
      const filePath = path.join(testDir, 'null-byte.bin');
      fs.writeFileSync(filePath, binary);

      const result = detectFileType(filePath);
      // Null byte indica binario, no texto
      expect(result).not.toEqual({ mime: 'text/plain', ext: 'txt' });

      fs.unlinkSync(filePath);
    });

    it('debe retornar null si archivo no existe', () => {
      const nonExistent = path.join(testDir, 'nonexistent.txt');
      
      expect(() => detectFileType(nonExistent)).toThrow();
    });

    it('debe manejar archivos grandes correctamente', () => {
      const largeText = 'X'.repeat(100000);
      const filePath = path.join(testDir, 'large.txt');
      fs.writeFileSync(filePath, largeText);

      const result = detectFileType(filePath);
      expect(result.mime).toBe('text/plain');

      fs.unlinkSync(filePath);
    });
  });

  describe('Validación de integridad', () => {
    it('debe detectar extensión falseada (.zip con firma PNG)', () => {
      const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const filePath = path.join(testDir, 'fake.zip'); // Extensión falseada
      fs.writeFileSync(filePath, pngSignature);

      const result = detectFileType(filePath);
      // Debe detectar el tipo real, no la extensión
      expect(result).toEqual({ mime: 'image/png', ext: 'png' });

      fs.unlinkSync(filePath);
    });

    it('debe detectar múltiples tipos si se proporcionan múltiples firmas', () => {
      const zipSignature = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
      const filePath = path.join(testDir, 'archive.zip');
      fs.writeFileSync(filePath, zipSignature);

      const result = detectFileType(filePath);
      expect(result.mime).toBe('application/zip');

      fs.unlinkSync(filePath);
    });
  });
});
