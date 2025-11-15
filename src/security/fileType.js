const fs = require('fs');

const MAGIC_NUMBERS = [
  {
    mime: 'image/png',
    ext: 'png',
    signatures: ['89504e470d0a1a0a'],
  },
  {
    mime: 'image/jpeg',
    ext: 'jpg',
    signatures: ['ffd8ffe0', 'ffd8ffe1', 'ffd8ffe2', 'ffd8ffe3', 'ffd8ffe8'],
  },
  {
    mime: 'image/gif',
    ext: 'gif',
    signatures: ['474946383761', '474946383961'],
  },
  {
    mime: 'application/pdf',
    ext: 'pdf',
    signatures: ['25504446'],
  },
  {
    mime: 'application/zip',
    ext: 'zip',
    signatures: ['504b0304', '504b0506', '504b0708'],
  },
  {
    mime: 'image/bmp',
    ext: 'bmp',
    signatures: ['424d'],
  },
];

function bufferToHex(buffer, length) {
  return buffer
    .subarray(0, length)
    .toString('hex')
    .toLowerCase();
}

function matchesSignature(buffer, signature) {
  const neededLength = signature.length / 2;
  const hex = bufferToHex(buffer, neededLength);
  return hex.startsWith(signature.toLowerCase());
}

function looksLikeText(buffer) {
  const slice = buffer.subarray(0, 256);
  let printable = 0;
  for (const byte of slice) {
    if (byte === 0) {
      return false;
    }
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      printable += 1;
    }
  }
  return printable / (slice.length || 1) > 0.9;
}

function detectFileType(filePath) {
  const buffer = fs.readFileSync(filePath);
  if (!buffer.length) {
    return null;
  }

  for (const entry of MAGIC_NUMBERS) {
    for (const signature of entry.signatures) {
      if (matchesSignature(buffer, signature)) {
        return { mime: entry.mime, ext: entry.ext };
      }
    }
  }

  if (looksLikeText(buffer)) {
    return { mime: 'text/plain', ext: 'txt' };
  }

  return null;
}

module.exports = { detectFileType };
