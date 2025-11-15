const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const { Server } = require('socket.io');
require('dotenv').config();

const Attendance = require('./src/models/Attendance');
const Admin = require('./src/models/Admin');
const Room = require('./src/models/Room');
const AuditLog = require('./src/models/AuditLog');
const rateLimiter = require('./src/security/rateLimiter');
const {
  encryptText,
  decryptText,
  hashSecret,
  verifyHash,
  generateSessionKey,
} = require('./src/security/crypto');
const { signToken, verifyToken } = require('./src/security/token');
const { verifyTotp } = require('./src/security/totp');
const { analyzeFile } = require('./src/security/stegAnalyzer');
const { detectFileType } = require('./src/security/fileType');

const PORT = process.env.PORT || 3000;
const MONGODB_URI =
  process.env.MONGODB_URI ||
  'mongodb+srv://gpcaceres_db_user:admin1234@cluster0.rhy84bz.mongodb.net/?appName=Cluster0';

const TOKEN_SECRET =
  process.env.TOKEN_SECRET || 'change-me-token-secret-change-me-token-secret';
const CRYPTO_SECRET =
  process.env.CRYPTO_SECRET || 'change-me-crypto-secret-change-me-crypto-secret';
const AUDIT_SECRET = process.env.AUDIT_SECRET || CRYPTO_SECRET;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

app.use(rateLimiter);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${crypto.randomInt(100000, 999999)}`;
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_');
    cb(null, `${uniqueSuffix}-${sanitized}`);
  },
});

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'application/pdf',
  'text/plain',
  'application/zip',
];

const upload = multer({
  storage,
  limits: {
    fileSize: 15 * 1024 * 1024,
  },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error('Tipo de archivo no permitido'));
    }
    return cb(null, true);
  },
});

app.use('/uploads', express.static(uploadsDir, { fallthrough: false }));
app.use(express.static(path.join(__dirname, 'public')));

const sessionRegistry = new Map();
const deviceRegistry = new Map();

async function audit(action, actor, metadata = {}) {
  const payload = JSON.stringify({ action, actor, metadata, timestamp: Date.now() });
  const signature = crypto.createHmac('sha256', AUDIT_SECRET).update(payload).digest('base64');
  try {
    await AuditLog.create({ action, actor, metadata, signature });
  } catch (error) {
    console.error('No se pudo registrar el log de auditoría', error);
  }
}

function getFingerprint(req) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const agent = req.headers['user-agent'] || 'unknown';
  return crypto.createHash('sha256').update(`${ip}:${agent}`).digest('hex');
}

function sanitizeNickname(nickname) {
  return nickname.trim().replace(/\s+/g, ' ');
}

async function ensureAdminAccount() {
  const username = (process.env.ADMIN_USERNAME || 'admin').trim();
  const password = process.env.ADMIN_PASSWORD || 'Admin#1234';
  const totpSecret = process.env.ADMIN_TOTP_SECRET || '';
  const existing = await Admin.findOne({ username });
  const { hash, salt, iterations } = hashSecret(password);
  if (existing) {
    existing.passwordHash = hash;
    existing.passwordSalt = salt;
    existing.passwordIterations = iterations;
    existing.totpSecret = totpSecret || existing.totpSecret;
    await existing.save();
    return existing;
  }
  const admin = await Admin.create({
    username,
    passwordHash: hash,
    passwordSalt: salt,
    passwordIterations: iterations,
    totpSecret,
  });
  await audit('admin_created', username, { by: 'system' });
  return admin;
}

async function authenticateAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [, token] = header.split(' ');
    if (!token) {
      return res.status(401).json({ message: 'Token requerido.' });
    }
    const payload = verifyToken(token, TOKEN_SECRET);
    if (payload.scope !== 'admin') {
      return res.status(403).json({ message: 'Acceso denegado.' });
    }
    const admin = await Admin.findById(payload.sub);
    if (!admin) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }
    req.admin = admin;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido.' });
  }
}

async function authenticateUser(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [, token] = header.split(' ');
    if (!token) {
      return res.status(401).json({ message: 'Token de sesión requerido.' });
    }
    const payload = verifyToken(token, TOKEN_SECRET);
    if (payload.scope !== 'user') {
      return res.status(403).json({ message: 'Rol inválido.' });
    }
    req.session = payload;
    next();
  } catch (_error) {
    return res.status(401).json({ message: 'Sesión inválida.' });
  }
}

function registerSession(roomId, nickname, nicknameHash, fingerprint) {
  if (!sessionRegistry.has(roomId)) {
    sessionRegistry.set(roomId, new Map());
  }
  const roomSessions = sessionRegistry.get(roomId);
  const normalized = nickname.toLowerCase();
  for (const [sessionId, session] of roomSessions.entries()) {
    if (session.fingerprint === fingerprint) {
      roomSessions.delete(sessionId);
    }
  }
  for (const session of roomSessions.values()) {
    if (session.nicknameNormalized === normalized) {
      throw new Error('El nickname ya está en uso en la sala.');
    }
  }

  if (deviceRegistry.has(fingerprint) && deviceRegistry.get(fingerprint) !== roomId) {
    throw new Error('Este dispositivo ya está unido a otra sala.');
  }

  const sessionId = crypto.randomUUID();
  roomSessions.set(sessionId, {
    nicknameHash,
    nicknameNormalized: normalized,
    fingerprint,
    connectedAt: new Date().toISOString(),
  });
  deviceRegistry.set(fingerprint, roomId);
  return sessionId;
}

function unregisterSession(roomId, sessionId) {
  const roomSessions = sessionRegistry.get(roomId);
  if (!roomSessions) return;
  const session = roomSessions.get(sessionId);
  roomSessions.delete(sessionId);
  if (session) {
    const stillActive = Array.from(roomSessions.values()).some(
      (value) => value.fingerprint === session.fingerprint
    );
    if (!stillActive) {
      deviceRegistry.delete(session.fingerprint);
    }
  }
  if (roomSessions.size === 0) {
    sessionRegistry.delete(roomId);
  }
}

function getRoomUsers(roomId) {
  const roomSessions = sessionRegistry.get(roomId);
  if (!roomSessions) return [];
  return Array.from(roomSessions.values()).map((value) => ({
    nicknameHash: value.nicknameHash,
    connectedAt: value.connectedAt,
  }));
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password, token } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Usuario y contraseña son obligatorios.' });
    }

    const admin = await Admin.findOne({ username: String(username).trim() });
    if (!admin) {
      await audit('admin_login_failed', username, { reason: 'not_found' });
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    const validPassword = verifyHash(
      password,
      admin.passwordHash,
      admin.passwordSalt,
      admin.passwordIterations
    );
    if (!validPassword) {
      await audit('admin_login_failed', username, { reason: 'invalid_password' });
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    if (!verifyTotp(token, admin.totpSecret)) {
      await audit('admin_login_failed', username, { reason: 'invalid_totp' });
      return res.status(401).json({ message: 'Token 2FA inválido.' });
    }

    admin.lastLoginAt = new Date();
    await admin.save();

    const sessionToken = signToken(
      {
        sub: admin._id.toString(),
        username: admin.username,
        scope: 'admin',
      },
      TOKEN_SECRET,
      3600
    );

    await audit('admin_login_success', username, { adminId: admin._id.toString() });

    return res.json({ token: sessionToken, expiresIn: 3600 });
  } catch (error) {
    console.error('Error en login admin:', error);
    return res.status(500).json({ message: 'No se pudo iniciar sesión.' });
  }
});

app.post('/api/admin/rooms', authenticateAdmin, async (req, res) => {
  try {
    const { type = 'text', pin, maxFileSizeMB = 10 } = req.body;
    if (!pin || String(pin).length < 4) {
      return res.status(400).json({ message: 'El PIN debe tener al menos 4 dígitos.' });
    }
    if (!['text', 'multimedia'].includes(type)) {
      return res.status(400).json({ message: 'Tipo de sala inválido.' });
    }

    const { hash, salt, iterations } = hashSecret(String(pin));
    const roomId = crypto.randomUUID();
    const encryptedId = encryptText(roomId, CRYPTO_SECRET);
    const sessionKey = generateSessionKey(CRYPTO_SECRET);

    const room = await Room.create({
      roomId,
      encryptedId,
      pinHash: hash,
      pinSalt: salt,
      pinIterations: iterations,
      type,
      maxFileSizeMB: Number(maxFileSizeMB) || 10,
      createdBy: req.admin._id,
      sessionKey,
    });

    await audit('room_created', req.admin.username, {
      roomId,
      type,
      maxFileSizeMB: room.maxFileSizeMB,
    });

    return res.status(201).json({
      roomId,
      encryptedId,
      type: room.type,
      maxFileSizeMB: room.maxFileSizeMB,
      createdAt: room.createdAt,
    });
  } catch (error) {
    console.error('Error creando sala:', error);
    return res.status(500).json({ message: 'No se pudo crear la sala.' });
  }
});

app.post('/api/rooms/access', async (req, res) => {
  try {
    const { roomId, pin, nickname } = req.body;
    if (!roomId || !pin || !nickname) {
      return res.status(400).json({ message: 'Sala, PIN y nickname son requeridos.' });
    }
    const sanitizedNickname = sanitizeNickname(nickname);
    if (sanitizedNickname.length < 3) {
      return res.status(400).json({ message: 'El nickname debe tener al menos 3 caracteres.' });
    }

    const room = await Room.findOne({ roomId });
    if (!room || !room.active) {
      return res.status(404).json({ message: 'Sala no encontrada o inactiva.' });
    }

    const validPin = verifyHash(pin, room.pinHash, room.pinSalt, room.pinIterations);
    if (!validPin) {
      await audit('room_access_denied', 'anonymous', { roomId, reason: 'invalid_pin' });
      return res.status(401).json({ message: 'PIN incorrecto.' });
    }

    const fingerprint = getFingerprint(req);
    const nicknameHash = crypto
      .createHash('sha256')
      .update(sanitizedNickname)
      .digest('base64');
    let sessionId;
    try {
      sessionId = registerSession(room.roomId, sanitizedNickname, nicknameHash, fingerprint);
    } catch (error) {
      return res.status(400).json({ message: error.message });
    }

    const sessionToken = signToken(
      {
        sub: sessionId,
        roomId: room.roomId,
        nicknameHash,
        displayName: sanitizedNickname,
        scope: 'user',
      },
      TOKEN_SECRET,
      3600
    );

    const sessionKey = decryptText(room.sessionKey, CRYPTO_SECRET);

    await audit('room_access_granted', sanitizedNickname, {
      roomId: room.roomId,
      nicknameHash,
    });

    return res.json({
      sessionToken,
      sessionKey,
      room: {
        id: room.roomId,
        type: room.type,
        maxFileSizeMB: room.maxFileSizeMB,
      },
      user: {
        nicknameHash,
        displayName: sanitizedNickname,
      },
    });
  } catch (error) {
    console.error('Error en acceso a sala:', error);
    return res.status(500).json({ message: 'No se pudo acceder a la sala.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name || !email) {
      return res.status(400).json({ message: 'Nombre y correo son obligatorios.' });
    }
    const normalizedEmail = String(email).toLowerCase();
    const record = await Attendance.create({
      name: name.trim(),
      email: normalizedEmail,
    });
    attendanceUsers.set(record._id.toString(), {
      name: record.name,
      email: record.email,
    });
    return res.status(201).json({
      id: record._id,
      name: record.name,
      email: record.email,
      createdAt: record.createdAt,
    });
  } catch (error) {
    console.error('Error storing attendance record', error);
    return res.status(500).json({ message: 'No se pudo registrar la asistencia.' });
  }
});

app.post('/api/rooms/:roomId/upload', authenticateUser, upload.single('file'), async (req, res) => {
  try {
    const { roomId } = req.params;
    const { roomId: sessionRoomId } = req.session;
    if (roomId !== sessionRoomId) {
      return res.status(403).json({ message: 'No autorizado para esta sala.' });
    }
    const room = await Room.findOne({ roomId });
    if (!room || room.type !== 'multimedia') {
      return res.status(403).json({ message: 'La sala no permite archivos multimedia.' });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'No se recibió archivo.' });
    }
    if (req.file.size > room.maxFileSizeMB * 1024 * 1024) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ message: 'El archivo excede el tamaño permitido.' });
    }

    const detectedType = detectFileType(req.file.path);
    if (!detectedType || !ALLOWED_MIME_TYPES.includes(detectedType.mime)) {
      fs.unlinkSync(req.file.path);
      await audit('file_rejected', req.session.displayName, {
        roomId,
        reason: 'Tipo de archivo no permitido',
        detectedMime: detectedType?.mime || 'desconocido',
      });
      return res.status(400).json({ message: 'Tipo de archivo no permitido.' });
    }
    if (detectedType.mime !== req.file.mimetype) {
      fs.unlinkSync(req.file.path);
      await audit('file_rejected', req.session.displayName, {
        roomId,
        reason: 'Firma y extensión no coinciden',
        reportedMime: req.file.mimetype,
        detectedMime: detectedType.mime,
      });
      io.to(roomId).emit('security_alert', {
        level: 'warning',
        message: 'Se bloqueó un archivo cuya firma no coincide con la extensión declarada.',
        detectedMime: detectedType.mime,
        reportedMime: req.file.mimetype,
        timestamp: new Date().toISOString(),
      });
      return res
        .status(400)
        .json({ message: 'El tipo real del archivo no coincide con su extensión.' });
    }

    const analysis = await analyzeFile(req.file.path);
    if (analysis.suspicious) {
      fs.unlinkSync(req.file.path);
      await audit('file_rejected', req.session.displayName, {
        roomId,
        entropy: analysis.entropy,
      });
      io.to(roomId).emit('security_alert', {
        level: 'warning',
        message: 'Archivo rechazado por posible esteganografía.',
        entropy: analysis.entropy,
        timestamp: new Date().toISOString(),
      });
      return res
        .status(400)
        .json({ message: 'Archivo rechazado por posible esteganografía.' });
    }

    await audit('file_uploaded', req.session.displayName, {
      roomId,
      filename: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });

    return res.status(201).json({
      originalName: req.file.originalname,
      filename: req.file.filename,
      size: req.file.size,
      mimetype: req.file.mimetype,
      url: `/uploads/${req.file.filename}`,
      entropy: analysis.entropy,
    });
  } catch (error) {
    console.error('Error al subir archivo:', error);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({ message: 'No se pudo procesar el archivo.' });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || err.message === 'Tipo de archivo no permitido') {
    return res.status(400).json({ message: err.message });
  }
  console.error('Error inesperado:', err);
  return res.status(500).json({ message: 'Error interno del servidor.' });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error('Token requerido'));
    }
    const payload = verifyToken(token, TOKEN_SECRET);
    if (payload.scope !== 'user') {
      return next(new Error('Token inválido'));
    }
    socket.data.session = payload;
    next();
  } catch (error) {
    next(error);
  }
});

io.on('connection', (socket) => {
  const { roomId, nicknameHash, displayName, sub } = socket.data.session || {};
  if (!roomId || !nicknameHash || !sub) {
    socket.disconnect(true);
    return;
  }

  socket.join(roomId);

  if (!sessionRegistry.has(roomId)) {
    sessionRegistry.set(roomId, new Map());
  }
  const roomSessions = sessionRegistry.get(roomId);
  if (!roomSessions.has(sub)) {
    socket.disconnect(true);
    return;
  }
  const session = roomSessions.get(sub);
  session.socketId = socket.id;
  session.connectedAt = new Date().toISOString();

  io.to(roomId).emit('system_message', {
    type: 'join',
    user: nicknameHash,
    timestamp: new Date().toISOString(),
  });
  io.to(roomId).emit('user_list', getRoomUsers(roomId));

  socket.on('chat_message', (message) => {
    if (!message || !message.payload) {
      return;
    }
    if (message.roomId !== roomId) {
      return;
    }

    io.to(roomId).emit('chat_message', {
      sender: nicknameHash,
      payload: message.payload,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('file_shared', (fileInfo) => {
    if (!fileInfo || !fileInfo.url || !fileInfo.filename) {
      return;
    }
    if (fileInfo.roomId !== roomId) {
      return;
    }

    io.to(roomId).emit('file_shared', {
      ...fileInfo,
      sender: nicknameHash,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('disconnect', () => {
    unregisterSession(roomId, sub);
    io.to(roomId).emit('user_list', getRoomUsers(roomId));
    io.to(roomId).emit('system_message', {
      type: 'leave',
      user: nicknameHash,
      timestamp: new Date().toISOString(),
    });
  });
});

async function start() {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    await ensureAdminAccount();
    console.log('Conectado a MongoDB');
    server.listen(PORT, () => {
      console.log(`Servidor escuchando en el puerto ${PORT}`);
    });
  } catch (error) {
    console.error('Error al conectar con MongoDB:', error.message);
    process.exit(1);
  }
}

start();
