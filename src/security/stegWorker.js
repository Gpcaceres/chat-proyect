const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { parentPort } = require('worker_threads');

const ENTROPY_SUSPICIOUS_THRESHOLD = 7.985;

function runPythonScan(filePath) {
  try {
    const scriptPath = path.join(__dirname, 'binwalk_scan.py');
    const result = spawnSync('python3', [scriptPath, filePath], {
      encoding: 'utf-8',
      maxBuffer: 2 * 1024 * 1024,
    });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      const message = result.stderr?.trim() || result.stdout?.trim() || 'scan_failed';
      return { supported: false, findings: [], tail_bytes: 0, error: message };
    }
    const parsed = JSON.parse(result.stdout || '{}');
    return {
      supported: Boolean(parsed.supported),
      findings: parsed.findings || [],
      anomalies: parsed.anomalies || [],
      tail_bytes: parsed.tail_bytes || 0,
      suspicious: Boolean(parsed.suspicious),
<<<<<<< HEAD
      steg_score: parsed.steg_score || 0,
      entropy: parsed.entropy || 0,
      indicators_count: parsed.indicators_count || 0,
    };
  } catch (error) {
    return { 
      supported: false, 
      findings: [], 
      tail_bytes: 0, 
      error: error.message,
      anomalies: [],
      suspicious: false,
=======
      lsb: parsed.lsb_analysis || null,
      stegProbe: parsed.steghide_probe || null,
    };
  } catch (error) {
    return {
      supported: false,
      findings: [],
      tail_bytes: 0,
      error: error.message,
      lsb: null,
      stegProbe: null,
>>>>>>> b07dfd1e4df73ca57b0cd74cb9df334606627cf2
    };
  }
}

function calculateEntropy(buffer) {
  const size = buffer.length;
  if (size === 0) {
    return 0;
  }
  const counts = new Array(256).fill(0);
  for (let i = 0; i < size; i += 1) {
    counts[buffer[i]] += 1;
  }
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / size;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function analyzeFileStructure(buffer, filePath) {
  const chunkSize = 1024;
  let compressionScore = 0;
  
  for (let i = 0; i < Math.min(buffer.length, 100000); i += chunkSize) {
    const chunk = buffer.slice(i, i + chunkSize);
    const chunkEntropy = calculateEntropy(chunk);
    if (chunkEntropy > 7.8) {
      compressionScore += 1;
    }
  }
  
  return compressionScore;
}

function detectStegPatterns(buffer) {
  /**
   * DETECCIÓN MÁXIMA AGRESIVA DE OPENSTEGO:
   * CUALQUIER dato después del fin de imagen = RECHAZAR
   */
  let stegScore = 0;
  const findings = [];
  
  // ==================== BUSCAR FIN DE IMAGEN ====================
  
  let imageEnd = { type: null, offset: -1, marker: null };
  
  // JPEG: buscar 0xFF 0xD9 más próximo al final
  for (let i = Math.max(0, buffer.length - 10000); i < buffer.length - 1; i++) {
    if (buffer[i] === 0xFF && buffer[i + 1] === 0xD9) {
      imageEnd = { type: 'JPEG', offset: i + 2, marker: '0xFF 0xD9' };
    }
  }
  
  // PNG: buscar IEND más próximo al final (0x49 0x45 0x4E 0x44)
  const iendSig = Buffer.from([0x49, 0x45, 0x4e, 0x44]);
  let iendIdx = buffer.lastIndexOf(iendSig);
  if (iendIdx > 0) {
    imageEnd = { type: 'PNG', offset: iendIdx + 4, marker: 'IEND' };
  }
  
  // GIF: buscar 0x3B más próximo al final
  for (let i = Math.max(0, buffer.length - 10000); i < buffer.length - 1; i++) {
    if (buffer[i] === 0x3B) {
      imageEnd = { type: 'GIF', offset: i + 1, marker: '0x3B' };
    }
  }
  
  // ==================== ANALIZAR COLA DESPUÉS DEL FIN ====================
  
  if (imageEnd.offset > 0 && imageEnd.offset < buffer.length) {
    const tailData = buffer.slice(imageEnd.offset);
    const tailSize = tailData.length;
    
    findings.push(`Image end: ${imageEnd.type} at offset ${imageEnd.offset}`);
    
    // MEDIDA 1: CUALQUIER DATO después del fin = SOSPECHOSO
    if (tailSize > 0) {
      findings.push(`⚠️ Tail data detected: ${tailSize} bytes (CUALQUIER dato = sospechoso)`);
      
      // MEDIDA 2: Buscar ZIP
      if (tailData.includes(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
        findings.push(`ZIP signature found → RECHAZAR`);
        return { stegScore: 0.99, patterns: findings, type: 'OPENSTEGO_ZIP', trustLevel: 'DEFINITE' };
      }
      
      // MEDIDA 3: Buscar GZIP
      if (tailData.includes(Buffer.from([0x1f, 0x8b]))) {
        findings.push(`GZIP signature found → RECHAZAR`);
        return { stegScore: 0.99, patterns: findings, type: 'OPENSTEGO_GZIP', trustLevel: 'DEFINITE' };
      }
      
      // MEDIDA 4: Buscar RAR
      if (tailData.includes(Buffer.from([0x52, 0x61, 0x72, 0x21]))) {
        findings.push(`RAR signature found → RECHAZAR`);
        return { stegScore: 0.99, patterns: findings, type: 'OPENSTEGO_RAR', trustLevel: 'DEFINITE' };
      }
      
      // MEDIDA 5: Buscar 7Z
      if (tailData.includes(Buffer.from([0x37, 0x7A, 0xBC, 0xAF]))) {
        findings.push(`7Z signature found → RECHAZAR`);
        return { stegScore: 0.99, patterns: findings, type: 'OPENSTEGO_7Z', trustLevel: 'DEFINITE' };
      }
      
      // MEDIDA 6: Tail muy grande (>50 bytes) = muy sospechoso
      if (tailSize > 50) {
        findings.push(`Large tail data (${tailSize} bytes) without compression signature = sospechoso`);
        const sampleEntropy = calculateEntropy(tailData.slice(0, Math.min(1000, tailSize)));
        if (sampleEntropy > 7.5) {
          findings.push(`High entropy in tail (${sampleEntropy.toFixed(2)}) = probable compression`);
          stegScore = 0.85;
        } else {
          stegScore = 0.70; // Incluso sin alta entropía
        }
      } else {
        // Pequeño tail (>0 bytes): también sospechoso
        findings.push(`Even small tail data (${tailSize} bytes) can indicate steganography`);
        stegScore = 0.75;
      }
      
      return { stegScore, patterns: findings, type: `${imageEnd.type}+Tail`, trustLevel: 'HIGH' };
    }
  }
  
  findings.push('No tail data detected - imagen normal');
  return {
    stegScore: 0,
    patterns: findings,
    imageType: imageEnd.type,
    imageEndOffset: imageEnd.offset,
    trustLevel: 'CLEAN'
  };
}

function detectByteDistributionAnomaly(buffer) {
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    counts[buffer[i]] += 1;
  }
  
  const expected = buffer.length / 256;
  let anomalyScore = 0;
  
  for (const count of counts) {
    const deviation = Math.abs(count - expected) / expected;
    if (deviation > 0.5) anomalyScore += 0.01;
  }
  
  return Math.min(anomalyScore, 1.0);
}

parentPort.on('message', (filePath) => {
  try {
    const buffer = fs.readFileSync(filePath);
    
    // PASO 1: DETECCIÓN ESPECÍFICA
    const stegAnalysis = detectStegPatterns(buffer);
    const entropy = calculateEntropy(buffer);
<<<<<<< HEAD
    
    let suspicious = false;
    let scanResult = null;
    let compressionScore = 0;
    let detectionReasons = {};
    
    /**
     * CRITERIO FINAL - MÁXIMAMENTE AGRESIVO:
     * 
     * RECHAZAR SI:
     * 1. stegScore > 0.70 = Probablemente OpenStego
     * 2. Tiene tail data + high entropy
     * 3. Python confirma CUALQUIER indicador
     */
    
    // MEDIDA 1: Score muy alto (>0.85) = DEFINITIVAMENTE rechazar
    if (stegAnalysis.stegScore > 0.85) {
      suspicious = true;
      scanResult = runPythonScan(filePath);
      
      detectionReasons = {
        reason: 'DEFINITE_OPENSTEGO_DETECTED',
        stegScore: stegAnalysis.stegScore.toFixed(2),
        patterns: stegAnalysis.patterns,
        trustLevel: stegAnalysis.trustLevel,
        status: 'REJECTED'
      };
    } 
    // MEDIDA 2: Score alto (0.70-0.85) = RECHAZAR sin necesidad de confirmación
    else if (stegAnalysis.stegScore > 0.70) {
      suspicious = true;
      scanResult = runPythonScan(filePath);
      
      detectionReasons = {
        reason: 'HIGH_STEG_PATTERN_DETECTED',
        stegScore: stegAnalysis.stegScore.toFixed(2),
        patterns: stegAnalysis.patterns,
        trustLevel: stegAnalysis.trustLevel,
        status: 'REJECTED'
      };
    }
    // MEDIDA 3: Score moderado (0.60-0.70) = verificar con Python
    else if (stegAnalysis.stegScore > 0.60) {
      scanResult = runPythonScan(filePath);
      const pythonSuspicious = scanResult && scanResult.suspicious === true;
      
      // Rechazar si Python TAMBIÉN lo marca o tiene muchos indicadores
      if (pythonSuspicious) {
        suspicious = true;
        detectionReasons = {
          reason: 'MODERATE_PATTERN_CONFIRMED_BY_PYTHON',
          stegScore: stegAnalysis.stegScore.toFixed(2),
          pythonResult: scanResult.suspicious,
          status: 'REJECTED'
        };
      } else {
        suspicious = false;
        detectionReasons = {
          reason: 'MODERATE_PATTERN_NOT_CONFIRMED',
          stegScore: stegAnalysis.stegScore.toFixed(2),
          status: 'ALLOWED'
        };
      }
    }
    // MEDIDA 4: Score bajo pero tiene tail data = verificar con Python
    else if (stegAnalysis.stegScore > 0.5) {
      scanResult = runPythonScan(filePath);
      const pythonSuspicious = scanResult && scanResult.suspicious === true;
      
      if (pythonSuspicious) {
        suspicious = true;
        detectionReasons = {
          reason: 'LOW_SCORE_BUT_PYTHON_CONFIRMS',
          stegScore: stegAnalysis.stegScore.toFixed(2),
          status: 'REJECTED'
        };
      } else {
        suspicious = false;
      }
    }
    // Score muy bajo: PERMITIR
    else {
      suspicious = false;
      detectionReasons = {
        reason: 'NO_STEG_PATTERN_DETECTED',
        stegScore: stegAnalysis.stegScore.toFixed(2),
        status: 'ALLOWED'
      };
    }
    
    parentPort.postMessage({ 
      entropy, 
      suspicious,
      binwalk: scanResult,
      compressionScore,
      stegAnalysis,
      detectionReasons,
      hasSteg: stegAnalysis.stegScore > 0.70,
      allPatterns: {
        entropy: entropy.toFixed(2),
        stegPatterns: stegAnalysis.patterns,
        trustLevel: stegAnalysis.trustLevel,
      }
=======
    const scanResult = runPythonScan(filePath);
    const suspiciousEntropy =
      entropy >= ENTROPY_SUSPICIOUS_THRESHOLD && scanResult.tail_bytes > 0;
    const lsbSuspicious = Boolean(scanResult.lsb?.suspicious);
    const stegSuspicious = Boolean(scanResult.stegProbe?.suspicious);
    const suspicious = Boolean(
      scanResult.suspicious || suspiciousEntropy || lsbSuspicious || stegSuspicious,
    );
    parentPort.postMessage({
      entropy,
      suspicious,
      binwalk: scanResult,
      lsb: scanResult.lsb,
      stegProbe: scanResult.stegProbe,
>>>>>>> b07dfd1e4df73ca57b0cd74cb9df334606627cf2
    });
  } catch (error) {
    // En caso de error, permitir por defecto
    parentPort.postMessage({ 
      error: error.message, 
      suspicious: false,
      entropy: 0,
      detectionReasons: { 
        reason: 'ERROR',
        error: error.message,
        status: 'allowed_on_error' 
      },
      allPatterns: { error: error.message },
      hasSteg: false
    });
  }
});