const fs = require('fs');
const { parentPort } = require('worker_threads');

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
    const suspicious = entropy > 7.5;
    parentPort.postMessage({ entropy, suspicious });
  } catch (error) {
    parentPort.postMessage({ error: error.message, suspicious: true, entropy: 8 });
  }
});
