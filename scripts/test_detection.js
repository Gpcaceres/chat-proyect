/**
 * Script de prueba para verificar detección de OpenStego
 * Crea imágenes de prueba y verifica la detección
 */

const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');

// Crear directorio de pruebas si no existe
const testDir = path.join(__dirname, '../test-images');
if (!fs.existsSync(testDir)) {
  fs.mkdirSync(testDir, { recursive: true });
}

/**
 * Crea un JPEG mínimo válido
 * Formato: SOI + APP0 + SOF + SOS + Datos + EOI
 */
function createMinimalJPEG() {
  const buffer = Buffer.alloc(100);
  let offset = 0;

  // SOI (Start of Image): 0xFF 0xD8
  buffer[offset++] = 0xFF;
  buffer[offset++] = 0xD8;

  // APP0 (JFIF): 0xFF 0xE0
  buffer[offset++] = 0xFF;
  buffer[offset++] = 0xE0;
  buffer[offset++] = 0x00;
  buffer[offset++] = 0x10; // Longitud
  buffer.write('JFIF\0', offset, 'binary');
  offset += 5;
  buffer[offset++] = 0x01; // Versión
  buffer[offset++] = 0x01;
  buffer[offset++] = 0x00; // Densidad X
  buffer[offset++] = 0x01;
  buffer[offset++] = 0x00;
  buffer[offset++] = 0x01;
  buffer[offset++] = 0x00;
  buffer[offset++] = 0x00;

  // Relleno con datos de imagen (simulado)
  for (let i = offset; i < 90; i++) {
    buffer[i] = Math.random() * 256;
  }

  // EOI (End of Image): 0xFF 0xD9
  buffer[98] = 0xFF;
  buffer[99] = 0xD9;

  return buffer;
}

/**
 * Crea un JPEG con OpenStego (datos embebidos después del fin)
 */
function createOpenStegoJPEG() {
  const normalJPEG = createMinimalJPEG();
  
  // Crear un archivo ZIP mínimo
  const zipHeader = Buffer.from([
    0x50, 0x4b, 0x03, 0x04, // Local file header
    0x0a, 0x00, // Version needed
    0x00, 0x00, // General flags
    0x00, 0x00, // Compression method
    0x00, 0x00, // Time
    0x00, 0x00, // Date
    0x00, 0x00, 0x00, 0x00, // CRC
    0x00, 0x00, 0x00, 0x00, // Compressed size
    0x00, 0x00, 0x00, 0x00, // Uncompressed size
    0x04, 0x00, // Filename length
    0x00, 0x00, // Extra field length
  ]);

  const fileName = Buffer.from('test', 'utf8');
  
  // Concatenar JPEG + ZIP
  const result = Buffer.concat([normalJPEG, zipHeader, fileName]);
  
  return result;
}

/**
 * Ejecuta el análisis usando el worker
 */
function analyzeFile(filePath) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, '../src/security/stegWorker.js'));
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('Timeout en análisis'));
    }, 10000);

    worker.once('message', (result) => {
      clearTimeout(timeout);
      worker.terminate();
      resolve(result);
    });

    worker.once('error', (error) => {
      clearTimeout(timeout);
      worker.terminate();
      reject(error);
    });

    worker.postMessage(filePath);
  });
}

/**
 * Ejecuta pruebas
 */
async function runTests() {
  console.log('🧪 Iniciando pruebas de detección de OpenStego\n');
  console.log('═'.repeat(60));

  try {
    // Prueba 1: JPEG normal
    console.log('\n✅ PRUEBA 1: JPEG Normal');
    console.log('─'.repeat(60));
    
    const normalPath = path.join(testDir, 'normal.jpg');
    const normalJPEG = createMinimalJPEG();
    fs.writeFileSync(normalPath, normalJPEG);
    
    console.log(`📁 Archivo creado: ${normalPath}`);
    console.log(`📊 Tamaño: ${normalJPEG.length} bytes`);
    
    const normalResult = await analyzeFile(normalPath);
    console.log(`\n🔍 Resultado del análisis:`);
    console.log(`   stegScore: ${normalResult.stegAnalysis.stegScore.toFixed(2)}`);
    console.log(`   suspicious: ${normalResult.suspicious}`);
    console.log(`   reason: ${normalResult.detectionReasons.reason}`);
    console.log(`   patterns: ${normalResult.stegAnalysis.patterns.join('; ')}`);
    
    const test1Pass = !normalResult.suspicious && normalResult.stegAnalysis.stegScore === 0;
    console.log(`\n${test1Pass ? '✅ PASÓ' : '❌ FALLÓ'}: JPEG normal debe ser permitido`);

    // Prueba 2: JPEG con OpenStego (ZIP embebido)
    console.log('\n\n✅ PRUEBA 2: JPEG con OpenStego (ZIP embebido)');
    console.log('─'.repeat(60));
    
    const openStegoPath = path.join(testDir, 'openstego.jpg');
    const openStegoJPEG = createOpenStegoJPEG();
    fs.writeFileSync(openStegoPath, openStegoJPEG);
    
    console.log(`📁 Archivo creado: ${openStegoPath}`);
    console.log(`📊 Tamaño: ${openStegoJPEG.length} bytes`);
    
    const openStegoResult = await analyzeFile(openStegoPath);
    console.log(`\n🔍 Resultado del análisis:`);
    console.log(`   stegScore: ${openStegoResult.stegAnalysis.stegScore.toFixed(2)}`);
    console.log(`   suspicious: ${openStegoResult.suspicious}`);
    console.log(`   reason: ${openStegoResult.detectionReasons.reason}`);
    console.log(`   patterns: ${openStegoResult.stegAnalysis.patterns.join('; ')}`);
    
    const test2Pass = openStegoResult.suspicious && openStegoResult.stegAnalysis.stegScore >= 0.95;
    console.log(`\n${test2Pass ? '✅ PASÓ' : '❌ FALLÓ'}: OpenStego debe ser rechazado`);

    // Prueba 3: JPEG con cola pequeña (potencial falso positivo)
    console.log('\n\n✅ PRUEBA 3: JPEG con cola pequeña no-comprimida');
    console.log('─'.repeat(60));
    
    const smallTailPath = path.join(testDir, 'small-tail.jpg');
    const smallTailJPEG = Buffer.concat([
      createMinimalJPEG(),
      Buffer.from([0x00, 0x01, 0x02]) // 3 bytes de cola
    ]);
    fs.writeFileSync(smallTailPath, smallTailJPEG);
    
    console.log(`📁 Archivo creado: ${smallTailPath}`);
    console.log(`📊 Tamaño: ${smallTailJPEG.length} bytes`);
    
    const smallTailResult = await analyzeFile(smallTailPath);
    console.log(`\n🔍 Resultado del análisis:`);
    console.log(`   stegScore: ${smallTailResult.stegAnalysis.stegScore.toFixed(2)}`);
    console.log(`   suspicious: ${smallTailResult.suspicious}`);
    console.log(`   reason: ${smallTailResult.detectionReasons.reason}`);
    
    const test3Pass = smallTailResult.suspicious; // Cualquier tail = sospechoso
    console.log(`\n${test3Pass ? '✅ PASÓ' : '⚠️  ADVERTENCIA'}: Cola pequeña detectada`);

    // Resumen
    console.log('\n\n' + '═'.repeat(60));
    console.log('📊 RESUMEN DE PRUEBAS');
    console.log('═'.repeat(60));
    console.log(`Prueba 1 (JPEG normal):        ${test1Pass ? '✅ PASÓ' : '❌ FALLÓ'}`);
    console.log(`Prueba 2 (OpenStego rechazado): ${test2Pass ? '✅ PASÓ' : '❌ FALLÓ'}`);
    console.log(`Prueba 3 (Cola detectada):    ${test3Pass ? '✅ PASÓ' : '⚠️  ALERTA'}`);
    
    const allPass = test1Pass && test2Pass;
    console.log(`\n${allPass ? '🎉 TODAS LAS PRUEBAS PASARON' : '⚠️  ALGUNAS PRUEBAS FALLARON'}`);

  } catch (error) {
    console.error('❌ Error durante las pruebas:', error.message);
    process.exit(1);
  }
}

// Ejecutar
runTests().then(() => {
  console.log('\n✅ Pruebas completadas');
  process.exit(0);
}).catch(error => {
  console.error('❌ Error:', error);
  process.exit(1);
});
