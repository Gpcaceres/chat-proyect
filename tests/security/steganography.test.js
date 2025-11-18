const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../../src/security/stegAnalyzer');

describe('Steganography Detection', () => {
  let testDir;

  beforeAll(() => {
    testDir = path.join(__dirname, '../../test_steg_files');
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(testDir)) {
      const files = fs.readdirSync(testDir);
      files.forEach(file => {
        fs.unlinkSync(path.join(testDir, file));
      });
      fs.rmdirSync(testDir);
    }
  });

  test('debe detectar imagen PNG normal como segura', async () => {
    // PNG válido mínimo
    const pngData = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
      0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
      0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
      0x54, 0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00,
      0x01, 0x01, 0x00, 0x00, 0x18, 0xdd, 0x8d, 0xb4,
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
      0xae, 0x42, 0x60, 0x82
    ]);
    
    const filePath = path.join(testDir, 'clean.png');
    fs.writeFileSync(filePath, pngData);
    
    const analysis = await analyzeFile(filePath);
    
    expect(analysis.entropy).toBeLessThan(7.0);
    expect(analysis.suspicious).toBe(false);
  }, 15000);

  test('debe detectar datos aleatorios como sospechosos', async () => {
    // Generar datos aleatorios (alta entropía = compresión/encriptación)
    const randomData = Buffer.alloc(10000);
    for (let i = 0; i < randomData.length; i++) {
      randomData[i] = Math.floor(Math.random() * 256);
    }
    
    const filePath = path.join(testDir, 'random.bin');
    fs.writeFileSync(filePath, randomData);
    
    const analysis = await analyzeFile(filePath);
    
    expect(analysis.entropy).toBeGreaterThan(7.5);
    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test('debe detectar entropía alta en chunks', async () => {
    // Crear PNG normal con datos aleatorios al final (esteganografía simulada)
    const pngHeader = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
      0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
      0x89
    ]);
    
    const pngFooter = Buffer.from([
      0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54,
      0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x18, 0xdd, 0x8d, 0xb4, 0x00,
      0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
      0x42, 0x60, 0x82
    ]);
    
    // Datos de esteganografía: aleatorios embebidos
    const stegData = Buffer.alloc(2000);
    for (let i = 0; i < stegData.length; i++) {
      stegData[i] = Math.floor(Math.random() * 256);
    }
    
    const filePath = path.join(testDir, 'steganographed.png');
    const combined = Buffer.concat([pngHeader, stegData, pngFooter]);
    fs.writeFileSync(filePath, combined);
    
    const analysis = await analyzeFile(filePath);
    
    // Debe detectar como sospechoso debido a:
    // 1. Datos con alta entropía incrustados
    // 2. Estructura anormal
    // 3. Posiblemente bytes de cola
    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test('debe detectar compresión anormal múltiple', async () => {
    // Crear un archivo con múltiples capas de datos comprimidos
    const compressedData = Buffer.alloc(5000);
    for (let i = 0; i < compressedData.length; i++) {
      compressedData[i] = Math.floor(Math.random() * 256);
    }
    
    const filePath = path.join(testDir, 'compressed.dat');
    fs.writeFileSync(filePath, compressedData);
    
    const analysis = await analyzeFile(filePath);
    
    expect(analysis.entropy).toBeGreaterThan(7.5);
    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test('debe incluir razones de detección', async () => {
    const randomData = Buffer.alloc(2000);
    for (let i = 0; i < randomData.length; i++) {
      randomData[i] = Math.floor(Math.random() * 256);
    }
    
    const filePath = path.join(testDir, 'detection_reasons.bin');
    fs.writeFileSync(filePath, randomData);
    
    const analysis = await analyzeFile(filePath);
    
    expect(analysis.detectionReasons).toBeDefined();
    expect(typeof analysis.detectionReasons).toBe('object');
    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test('debe reportar compression score para análisis detallado', async () => {
    const randomData = Buffer.alloc(3000);
    for (let i = 0; i < randomData.length; i++) {
      randomData[i] = Math.floor(Math.random() * 256);
    }
    
    const filePath = path.join(testDir, 'compression_score.bin');
    fs.writeFileSync(filePath, randomData);
    
    const analysis = await analyzeFile(filePath);
    
    expect(analysis.compressionScore).toBeDefined();
    expect(typeof analysis.compressionScore).toBe('number');
    expect(analysis.compressionScore).toBeGreaterThanOrEqual(0);
  }, 15000);
});
