const WINDOW_MS = 60 * 1000;
const MAX_REQUESTS = 100;

const buckets = new Map();

function cleanup() {
  const now = Date.now();
  for (const [key, bucket] of buckets.entries()) {
    if (now - bucket.start >= WINDOW_MS) {
      buckets.delete(key);
    }
  }
}

setInterval(cleanup, WINDOW_MS).unref();

function rateLimiter(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  if (!buckets.has(key)) {
    buckets.set(key, { start: now, count: 0 });
  }
  const bucket = buckets.get(key);
  if (now - bucket.start >= WINDOW_MS) {
    bucket.start = now;
    bucket.count = 0;
  }
  bucket.count += 1;
  if (bucket.count > MAX_REQUESTS) {
    return res.status(429).json({ message: 'Demasiadas solicitudes. Intente más tarde.' });
  }
  next();
}

module.exports = rateLimiter;
