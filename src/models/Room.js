// ==================== MODELO: SALA DE CHAT ====================
const mongoose = require('mongoose');

/**
 * Schema para ID Cifrado
 * Estructura para almacenar datos cifrados con AES-256-GCM
 */
const EncryptedIdSchema = new mongoose.Schema(
  {
    iv: { type: String, required: true }, // IV en base64
    content: { type: String, required: true }, // Contenido cifrado en base64
    authTag: { type: String, required: true }, // Tag de autenticación en base64
  },
  { _id: false } // No generar _id automático
);

/**
 * Schema de Sala de Chat
 * Representa una sala segura para comunicación E2E
 */
const RoomSchema = new mongoose.Schema(
  {
    // ID único de la sala (UUID)
    roomId: { type: String, required: true, unique: true },
    
    // ID de la sala cifrado con AES-256-GCM (para envíos seguros)
    encryptedId: { type: EncryptedIdSchema, required: true },
    
    // Hash PBKDF2 del PIN de acceso
    pinHash: { type: String, required: true },
    
    // Salt aleatorio del PIN
    pinSalt: { type: String, required: true },
    
    // Iteraciones PBKDF2 del PIN
    pinIterations: { type: Number, required: true },
    
    // Tipo de sala: 'text' (solo mensajes) o 'multimedia' (+ archivos)
    type: {
      type: String,
      enum: ['text', 'multimedia'],
      required: true,
      default: 'text',
    },
    
    // Tamaño máximo de archivo permitido (en MB)
    maxFileSizeMB: { type: Number, default: 10 },
    
    // Referencia al admin que creó la sala
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    
    // Bandera: si la sala está activa o ha sido desactivada
    active: { type: Boolean, default: true },
    
    // Clave de sesión cifrada para cifrado E2E en cliente
    // Estructura: { iv, content, authTag }
    sessionKey: {
      iv: String,
      content: String,
      authTag: String,
    },
  },
  // Agregar createdAt, updatedAt automáticamente
  { timestamps: true }
);

module.exports = mongoose.models.Room || mongoose.model('Room', RoomSchema);
