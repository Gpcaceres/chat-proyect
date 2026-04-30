const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { parentPort } = require("worker_threads");

const ENTROPY_SUSPICIOUS_THRESHOLD = 7.985;

function runPythonScan(filePath) {
  try {
    const scriptPath = path.join(__dirname, "binwalk_scan.py");
    const result = spawnSync("python3", [scriptPath, filePath], {
      encoding: "utf-8",
      maxBuffer: 2 * 1024 * 1024,
    });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      const message =
        result.stderr?.trim() || result.stdout?.trim() || "scan_failed";
      return { supported: false, findings: [], tail_bytes: 0, error: message };
    }
    const parsed = JSON.parse(result.stdout || "{}");
    return {
      supported: Boolean(parsed.supported),
      findings: parsed.findings || [],
      anomalies: parsed.anomalies || [],
      tail_bytes: parsed.tail_bytes || 0,
      suspicious: Boolean(parsed.suspicious),
      steg_score: parsed.steg_score || 0,
      entropy: parsed.entropy || 0,
      indicators_count: parsed.indicators_count || 0,
      scores: parsed.scores || {},
      lsb_analysis: parsed.lsb_analysis || null,
      steghide_probe: parsed.steghide_probe || null,
    };
  } catch (error) {
    return {
      supported: false,
      findings: [],
      tail_bytes: 0,
      error: error.message,
      anomalies: [],
      suspicious: false,
      lsb_analysis: null,
      steghide_probe: null,
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
    if (buffer[i] === 0xff && buffer[i + 1] === 0xd9) {
      imageEnd = { type: "JPEG", offset: i + 2, marker: "0xFF 0xD9" };
    }
  }

  // PNG: buscar IEND + CRC completo (8 bytes) para no incluir el CRC como tail
  // El CRC de IEND es siempre 0xAE426082 (CRC32 de "IEND")
  const iendFullSig = Buffer.from([
    0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
  ]);
  let iendIdx = buffer.lastIndexOf(iendFullSig);
  if (iendIdx > 0) {
    imageEnd = { type: "PNG", offset: iendIdx + 8, marker: "IEND+CRC" };
  }

  // GIF: buscar 0x3B más próximo al final
  for (let i = Math.max(0, buffer.length - 10000); i < buffer.length - 1; i++) {
    if (buffer[i] === 0x3b) {
      imageEnd = { type: "GIF", offset: i + 1, marker: "0x3B" };
    }
  }

  // ==================== ANALIZAR COLA DESPUÉS DEL FIN ====================

  if (imageEnd.offset > 0 && imageEnd.offset < buffer.length) {
    const tailData = buffer.slice(imageEnd.offset);
    const tailSize = tailData.length;

    findings.push(`Image end: ${imageEnd.type} at offset ${imageEnd.offset}`);

    // MEDIDA 1: verificar tail data
    if (tailSize > 0) {
      // Null-byte-only tails of ≤10 bytes are natural JPEG camera padding → not suspicious
      const isNullPadding = tailSize <= 10 && tailData.every((b) => b === 0x00);
      if (isNullPadding) {
        findings.push(
          `Natural null-byte padding (${tailSize} bytes) - not suspicious`,
        );
        return {
          stegScore: 0,
          patterns: findings,
          imageType: imageEnd.type,
          trustLevel: "CLEAN",
        };
      }

      findings.push(
        `Tail data detected: ${tailSize} bytes after ${imageEnd.type} end marker`,
      );

      // MEDIDA 2: Buscar ZIP
      if (tailData.includes(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
        findings.push(`ZIP signature found → RECHAZAR`);
        return {
          stegScore: 0.99,
          patterns: findings,
          type: "OPENSTEGO_ZIP",
          trustLevel: "DEFINITE",
        };
      }

      // MEDIDA 3: Buscar GZIP
      if (tailData.includes(Buffer.from([0x1f, 0x8b]))) {
        findings.push(`GZIP signature found → RECHAZAR`);
        return {
          stegScore: 0.99,
          patterns: findings,
          type: "OPENSTEGO_GZIP",
          trustLevel: "DEFINITE",
        };
      }

      // MEDIDA 4: Buscar RAR
      if (tailData.includes(Buffer.from([0x52, 0x61, 0x72, 0x21]))) {
        findings.push(`RAR signature found → RECHAZAR`);
        return {
          stegScore: 0.99,
          patterns: findings,
          type: "OPENSTEGO_RAR",
          trustLevel: "DEFINITE",
        };
      }

      // MEDIDA 5: Buscar 7Z
      if (tailData.includes(Buffer.from([0x37, 0x7a, 0xbc, 0xaf]))) {
        findings.push(`7Z signature found → RECHAZAR`);
        return {
          stegScore: 0.99,
          patterns: findings,
          type: "OPENSTEGO_7Z",
          trustLevel: "DEFINITE",
        };
      }

      // Size-based scoring — no archive signature found
      if (tailSize > 500) {
        findings.push(
          `Large tail data (${tailSize} bytes) without compression signature`,
        );
        const sampleEntropy = calculateEntropy(
          tailData.slice(0, Math.min(1000, tailSize)),
        );
        if (sampleEntropy > 7.5) {
          findings.push(
            `High entropy in tail (${sampleEntropy.toFixed(2)}) - compressed data likely`,
          );
          stegScore = 0.6;
        } else {
          stegScore = 0.45;
        }
      } else if (tailSize > 50) {
        findings.push(`Medium tail (${tailSize} bytes) - could be metadata`);
        stegScore = 0.4;
      } else {
        findings.push(
          `Small non-null tail (${tailSize} bytes) - low suspicion`,
        );
        stegScore = 0.25;
      }

      return {
        stegScore,
        patterns: findings,
        type: `${imageEnd.type}+Tail`,
        trustLevel: "LOW",
      };
    }
  }

  findings.push("No tail data detected - imagen normal");
  return {
    stegScore: 0,
    patterns: findings,
    imageType: imageEnd.type,
    imageEndOffset: imageEnd.offset,
    trustLevel: "CLEAN",
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

parentPort.on("message", (filePath) => {
  try {
    const buffer = fs.readFileSync(filePath);

    // PASO 1: DETECCIÓN ESPECÍFICA
    const stegAnalysis = detectStegPatterns(buffer);
    const entropy = calculateEntropy(buffer);

    // Layer 2: Python scanner (LSB, steghide, entropy distribution, binwalk)
    const scanResult = runPythonScan(filePath);
    const compressionScore = analyzeFileStructure(buffer, filePath);

    // Weighted multi-layer scoring
    // JS-side tail detection is the most reliable for OpenStego
    const jsScore = stegAnalysis.stegScore || 0;
    // Python LSB analysis
    const lsbResult = scanResult.lsb_analysis || {};
    const lsbScore =
      lsbResult.score != null
        ? lsbResult.score
        : lsbResult.suspicious
          ? 0.7
          : 0;
    // Steghide probe
    const steghideResult = scanResult.steghide_probe || {};
    let steghideScore = 0;
    if (steghideResult.suspicious) {
      const status = steghideResult.status || "";
      steghideScore =
        status === "embedded_data"
          ? 0.95
          : status === "password_protected"
            ? 0.85
            : status === "possibly_encrypted"
              ? 0.75
              : 0.7;
    }
    // Binwalk archive findings
    const binwalkScore =
      scanResult.findings && scanResult.findings.length > 0 ? 0.8 : 0;
    // Python's own aggregated steg_score (entropy jump, chi-square, etc.)
    const pythonScore = scanResult.steg_score || 0;

    const allScores = {
      js: jsScore,
      python: pythonScore,
      lsb: lsbScore,
      steghide: steghideScore,
      binwalk: binwalkScore,
    };

    // Take the highest individual score
    let finalScore = Math.max(...Object.values(allScores));

    // Boost confidence when 2+ independent signals agree.
    // pythonScore and lsbScore both originate from the same Python LSB analysis,
    // so merge them into a single combined signal to avoid inflating the count.
    const combinedPythonLsb = Math.max(pythonScore, lsbScore);
    const independentSignals = [
      jsScore,
      combinedPythonLsb,
      steghideScore,
      binwalkScore,
    ];
    const signalsFiring = independentSignals.filter((s) => s >= 0.5).length;
    if (signalsFiring >= 2) {
      finalScore = Math.min(finalScore + 0.1, 1.0);
    }

    // Threshold: reject when confidence >= 0.65
    const hasSteg = finalScore >= 0.65;
    const suspicious = hasSteg;

    let reason;
    if (!suspicious) {
      reason = "NO_STEG_DETECTED";
    } else if (stegAnalysis.trustLevel === "DEFINITE" || jsScore >= 0.95) {
      reason = "DEFINITE_OPENSTEGO_DETECTED";
    } else if (steghideScore >= 0.65) {
      reason = "STEGHIDE_CONFIRMED";
    } else if (lsbScore >= 0.65) {
      reason = "LSB_ANOMALY_DETECTED";
    } else if (jsScore >= 0.65 || pythonScore >= 0.65) {
      reason = "HIGH_STEG_SCORE";
    } else {
      reason = "MULTIPLE_SIGNALS";
    }

    const detectionReasons = {
      reason,
      finalScore: finalScore.toFixed(2),
      scores: allScores,
      signalsFiring,
      patterns: stegAnalysis.patterns,
      trustLevel: stegAnalysis.trustLevel,
      status: suspicious ? "REJECTED" : "ALLOWED",
    };

    parentPort.postMessage({
      entropy,
      suspicious,
      binwalk: scanResult,
      compressionScore,
      stegAnalysis,
      detectionReasons,
      hasSteg,
      allPatterns: {
        entropy: entropy.toFixed(2),
        stegPatterns: stegAnalysis.patterns,
        trustLevel: stegAnalysis.trustLevel,
      },
    });
  } catch (error) {
    // En caso de error, permitir por defecto
    parentPort.postMessage({
      error: error.message,
      suspicious: false,
      entropy: 0,
      detectionReasons: {
        reason: "ERROR",
        error: error.message,
        status: "allowed_on_error",
      },
      allPatterns: { error: error.message },
      hasSteg: false,
    });
  }
});
