// ==================== MODELO: ASISTENCIA ====================
const mongoose = require('mongoose');

/**
 * Schema de Registro de Asistencia
 * Registra cuándo y quién accedió al chat
 * Permite duplicados (mismo usuario/email puede registrarse múltiples veces)
 */
const attendanceSchema = new mongoose.Schema(
  {
    // Nombre del usuario que se conectó
    name: {
      type: String,
      required: true,
      trim: true,
    },
    
    // Correo electrónico del usuario
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true, // Normalizar a minúsculas
    },
  },
  {
    // createdAt: sí, updatedAt: no
    // Solo registramos cuándo se creó el registro
    timestamps: { createdAt: true, updatedAt: false },
  }
);

module.exports = mongoose.model('Attendance', attendanceSchema);
