const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const { Server } = require('socket.io');
require('dotenv').config();

const Attendance = require('./src/models/Attendance');

const PORT = process.env.PORT || 3000;
const MONGODB_URI =
  process.env.MONGODB_URI ||
  'mongodb+srv://gpcaceres_db_user:admin1234@cluster0.rhy84bz.mongodb.net/?appName=Cluster0';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_');
    cb(null, `${uniqueSuffix}-${sanitized}`);
  },
});

const upload = multer({ storage });

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

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

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No se recibió archivo.' });
  }

  return res.status(201).json({
    originalName: req.file.originalname,
    filename: req.file.filename,
    size: req.file.size,
    mimetype: req.file.mimetype,
    url: `/uploads/${req.file.filename}`,
  });
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const onlineUsers = new Map();

io.on('connection', (socket) => {
  socket.on('join', (payload) => {
    if (!payload || !payload.name || !payload.email) {
      return;
    }

    const user = {
      id: socket.id,
      name: payload.name,
      email: payload.email,
      joinedAt: new Date().toISOString(),
    };

    onlineUsers.set(socket.id, user);
    io.emit('user_list', Array.from(onlineUsers.values()));

    io.emit('system_message', {
      type: 'join',
      user: user.name,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('chat_message', (message) => {
    if (!message || !message.text || !message.sender) {
      return;
    }

    io.emit('chat_message', {
      text: message.text,
      sender: message.sender,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('file_shared', (fileInfo) => {
    if (!fileInfo || !fileInfo.url || !fileInfo.sender) {
      return;
    }

    io.emit('file_shared', {
      ...fileInfo,
      timestamp: new Date().toISOString(),
    });
  });

  socket.on('disconnect', () => {
    const user = onlineUsers.get(socket.id);
    onlineUsers.delete(socket.id);
    io.emit('user_list', Array.from(onlineUsers.values()));

    if (user) {
      io.emit('system_message', {
        type: 'leave',
        user: user.name,
        timestamp: new Date().toISOString(),
      });
    }
  });
});

async function start() {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
    });
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
