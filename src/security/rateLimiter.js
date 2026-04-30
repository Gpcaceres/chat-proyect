// ==================== LIMITADOR DE VELOCIDAD (Rate Limiter) ====================
// Algoritmo: Token Bucket por IP

// Ventana de tiempo: 60 segundos
const WINDOW_MS = 60 * 1000;

// Máximo de solicitudes por ventana por IP
const MAX_REQUESTS = 100;

// Mapa de buckets: ip → {start, count}
// start: timestamp de inicio de la ventana
// count: número de solicitudes en esta ventana
const buckets = new Map();

/**
 * Limpia buckets expirados
 * Se ejecuta cada WINDOW_MS para evitar fuga de memoria
 */
function cleanup() {
  const now = Date.now();
  // Iterar sobre copia de keys para evitar modificar durante iteración
  for (const [key, bucket] of buckets.entries()) {
    // Si ventana expiró (>60 segundos), eliminar bucket
    if (now - bucket.start >= WINDOW_MS) {
      buckets.delete(key);
    }
  }
}

// Ejecutar limpieza cada 60 segundos
// unref() permite que proceso termine sin esperar este timer
setInterval(cleanup, WINDOW_MS).unref();

/**
 * Middleware Express: Limitador de velocidad
 * @param {object} req - Request de Express
 * @param {object} res - Response de Express
 * @param {function} next - Siguiente middleware
 */
function rateLimiter(req, res, next) {
  // Usar IP del cliente como clave
  const key = req.ip;
  const now = Date.now();
  
  // Crear bucket si no existe
  if (!buckets.has(key)) {
    buckets.set(key, { start: now, count: 0 });
  }
  
  const bucket = buckets.get(key);
  
  // Si ventana expiró, resetear
  if (now - bucket.start >= WINDOW_MS) {
    bucket.start = now;
    bucket.count = 0;
  }
  
  // Incrementar contador
  bucket.count += 1;
  
  // Si excedió límite, rechazar con 429 (Too Many Requests)
  if (bucket.count > MAX_REQUESTS) {
    return res.status(429).json({ message: 'Demasiadas solicitudes. Intente más tarde.' });
  }
  
  // Continuar a siguiente middleware
  next();
}

module.exports = rateLimiter;
