const path = require('path');
const { Worker } = require('worker_threads');

function analyzeFile(filePath) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'stegWorker.js'));
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('Análisis de esteganografía excedió el tiempo límite'));
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

module.exports = { analyzeFile };
