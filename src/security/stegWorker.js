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
      tail_bytes: parsed.tail_bytes || 0,
      suspicious: Boolean(parsed.suspicious),
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

parentPort.on('message', (filePath) => {
  try {
    const buffer = fs.readFileSync(filePath);
    const entropy = calculateEntropy(buffer);
    const scanResult = runPythonScan(filePath);
    const entropyExceeded = Number.isFinite(entropy) && entropy >= ENTROPY_SUSPICIOUS_THRESHOLD;
    const suspiciousEntropy = entropyExceeded;
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
      entropyExceeded,
      entropyThreshold: ENTROPY_SUSPICIOUS_THRESHOLD,
    });
  } catch (error) {
    parentPort.postMessage({ error: error.message, suspicious: true, entropy: 8 });
  }
});
