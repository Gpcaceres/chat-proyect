const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../src/security/stegAnalyzer');

(async () => {
  const tmpDir = path.join(__dirname, '..', 'tmp_test');
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir);

  // 1) Imagen normal: JPEG minimal (SOI + minimal data + EOI)
  const normalPath = path.join(tmpDir, 'normal.jpg');
  const normalBuf = Buffer.concat([
    Buffer.from([0xFF, 0xD8]), // SOI
    Buffer.from([0xFF, 0xE0, 0x00, 0x10]), // APP0
    Buffer.from('JFIF\x00', 'ascii'),
    Buffer.alloc(100, 0x20), // some payload
    Buffer.from([0xFF, 0xD9]) // EOI
  ]);
  fs.writeFileSync(normalPath, normalBuf);

  // 2) OpenStego-like: JPEG + EOI + ZIP local header + some bytes
  const stegoPath = path.join(tmpDir, 'openstego.jpg');
  const zipHeader = Buffer.from([0x50,0x4B,0x03,0x04, 0x14,0x00,0x00,0x00]);
  const stegoBuf = Buffer.concat([
    Buffer.from([0xFF, 0xD8]),
    Buffer.alloc(100, 0x30),
    Buffer.from([0xFF, 0xD9]),
    zipHeader,
    Buffer.alloc(1024, 0x41)
  ]);
  fs.writeFileSync(stegoPath, stegoBuf);

  console.log('\nRunning stego analysis tests...');

  try {
    const resNormal = await analyzeFile(normalPath);
    console.log('\n== Normal Image Analysis ==');
    console.log('suspicious:', resNormal.suspicious);
    console.log('hasSteg:', resNormal.hasSteg || (resNormal.stegAnalysis && resNormal.stegAnalysis.stegScore > 0.8));
    console.log('stegAnalysis:', resNormal.stegAnalysis);
    console.log('detectionReasons:', resNormal.detectionReasons);
  } catch (e) {
    console.error('Error analyzing normal image:', e);
  }

  try {
    const resStego = await analyzeFile(stegoPath);
    console.log('\n== OpenStego-like Image Analysis ==');
    console.log('suspicious:', resStego.suspicious);
    console.log('hasSteg:', resStego.hasSteg || (resStego.stegAnalysis && resStego.stegAnalysis.stegScore > 0.8));
    console.log('stegAnalysis:', resStego.stegAnalysis);
    console.log('detectionReasons:', resStego.detectionReasons);
  } catch (e) {
    console.error('Error analyzing stego image:', e);
  }

  console.log('\nTest files created in:', tmpDir);
})();
