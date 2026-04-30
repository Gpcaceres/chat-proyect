// ==================== MODELO: ADMIN ====================
const mongoose = require('mongoose');

/**
 * Schema de Administrador
 * Almacena credenciales de usuario administrador con 2FA
 */
const AdminSchema = new mongoose.Schema(
  {
    // Nombre de usuario único
    username: { type: String, required: true, unique: true, trim: true },
    
    // Hash de contraseña (PBKDF2-SHA256)
    passwordHash: { type: String, required: true },
    
    // Salt aleatorio (base64)
    passwordSalt: { type: String, required: true },
    
    // Número de iteraciones PBKDF2
    passwordIterations: { type: Number, required: true },
    
    // Secreto base64 para TOTP 2FA (opcional)
    totpSecret: { type: String },
    
    // Roles del usuario (actualmente solo 'admin')
    roles: {
      type: [String],
      default: ['admin'],
      validate: {
        validator: (value) => value.every((role) => ['admin'].includes(role)),
        message: 'Rol no permitido',
      },
    },
    
    // Timestamp del último login exitoso
    lastLoginAt: { type: Date },
  },
  // Agregar campos: createdAt, updatedAt automáticamente
  { timestamps: true }
);

// Exportar modelo (singleton: reutiliza modelo si ya existe)
module.exports = mongoose.models.Admin || mongoose.model('Admin', AdminSchema);
