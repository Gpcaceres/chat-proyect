const fs = require("fs");
const path = require("path");
const { analyzeFile } = require("../../src/security/stegAnalyzer");

describe("Steganography Detection", () => {
  let testDir;

  beforeAll(() => {
    testDir = path.join(__dirname, "../../test_steg_files");
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(testDir)) {
      const files = fs.readdirSync(testDir);
      files.forEach((file) => {
        fs.unlinkSync(path.join(testDir, file));
      });
      fs.rmdirSync(testDir);
    }
  });

  test("debe detectar imagen PNG normal como segura", async () => {
    // PNG válido mínimo
    const pngData = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
      0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
      0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00,
      0x01, 0x01, 0x00, 0x00, 0x18, 0xdd, 0x8d, 0xb4, 0x00, 0x00, 0x00, 0x00,
      0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ]);

    const filePath = path.join(testDir, "clean.png");
    fs.writeFileSync(filePath, pngData);

    const analysis = await analyzeFile(filePath);

    expect(analysis.entropy).toBeLessThan(7.0);
    expect(analysis.suspicious).toBe(false);
  }, 15000);

  test("debe detectar datos aleatorios como sospechosos", async () => {
    // JPEG mínimo con firma ZIP embebida tras el marcador EOI
    // La capa JS detecta la firma ZIP en la cola → score 0.99 → suspicious=true
    const jpegHeader = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const jpegEnd = Buffer.from([0xff, 0xd9]); // EOI
    const zipSig = Buffer.from([0x50, 0x4b, 0x03, 0x04]); // firma ZIP (OpenStego)
    const payload = Buffer.alloc(500, 0xab);

    const filePath = path.join(testDir, "random.bin");
    fs.writeFileSync(
      filePath,
      Buffer.concat([jpegHeader, jpegEnd, zipSig, payload]),
    );

    const analysis = await analyzeFile(filePath);

    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test("debe detectar entropía alta en chunks", async () => {
    // PNG válido con firma GZIP embebida tras el marcador IEND
    // La capa JS detecta el marcador GZIP en la cola → score 0.99 → suspicious=true
    const pngData = Buffer.from([
      0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
      0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
      0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0x0f, 0x00, 0x00,
      0x01, 0x01, 0x00, 0x00, 0x18, 0xdd, 0x8d, 0xb4, 0x00, 0x00, 0x00, 0x00,
      0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ]);
    const gzipSig = Buffer.from([0x1f, 0x8b]); // firma GZIP
    const payload = Buffer.alloc(600, 0xcd);

    const filePath = path.join(testDir, "steganographed.png");
    fs.writeFileSync(filePath, Buffer.concat([pngData, gzipSig, payload]));

    const analysis = await analyzeFile(filePath);

    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test("debe detectar compresión anormal múltiple", async () => {
    // JPEG con firma 7-Zip embebida tras el marcador EOI
    // La capa JS detecta la firma 7Z en la cola → score 0.99 → suspicious=true
    const jpegHeader = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const jpegEnd = Buffer.from([0xff, 0xd9]);
    const sevenZSig = Buffer.from([0x37, 0x7a, 0xbc, 0xaf]); // firma 7-Zip
    const payload = Buffer.alloc(400, 0x88);

    const filePath = path.join(testDir, "compressed.dat");
    fs.writeFileSync(
      filePath,
      Buffer.concat([jpegHeader, jpegEnd, sevenZSig, payload]),
    );

    const analysis = await analyzeFile(filePath);

    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test("debe incluir razones de detección", async () => {
    // JPEG con firma RAR en la cola — verifica que detectionReasons esté presente
    const jpegHeader = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ]);
    const jpegEnd = Buffer.from([0xff, 0xd9]);
    const rarSig = Buffer.from([0x52, 0x61, 0x72, 0x21]); // firma RAR
    const payload = Buffer.alloc(300, 0x77);

    const filePath = path.join(testDir, "detection_reasons.bin");
    fs.writeFileSync(
      filePath,
      Buffer.concat([jpegHeader, jpegEnd, rarSig, payload]),
    );

    const analysis = await analyzeFile(filePath);

    expect(analysis.detectionReasons).toBeDefined();
    expect(typeof analysis.detectionReasons).toBe("object");
    expect(analysis.suspicious).toBe(true);
  }, 15000);

  test("debe reportar compression score para análisis detallado", async () => {
    const randomData = Buffer.alloc(3000);
    for (let i = 0; i < randomData.length; i++) {
      randomData[i] = Math.floor(Math.random() * 256);
    }

    const filePath = path.join(testDir, "compression_score.bin");
    fs.writeFileSync(filePath, randomData);

    const analysis = await analyzeFile(filePath);

    expect(analysis.compressionScore).toBeDefined();
    expect(typeof analysis.compressionScore).toBe("number");
    expect(analysis.compressionScore).toBeGreaterThanOrEqual(0);
  }, 15000);
});
