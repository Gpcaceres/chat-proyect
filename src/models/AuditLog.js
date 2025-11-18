// ==================== MODELO: LOG DE AUDITORÍA ====================
const mongoose = require('mongoose');

/**
 * Schema de Log de Auditoría\n * Registra todas las acciones importantes para trazabilidad
 */
const AuditLogSchema = new mongoose.Schema(
  {
    // Tipo de acción auditada\n    // Ejemplos: 'admin_login_success', 'room_access_granted', 'file_uploaded'
    action: { type: String, required: true },
    
    // Usuario que realizó la acción\n    // Puede ser nombre de admin, nickname de usuario, o 'system'
    actor: { type: String, required: true },
    
    // Información contextual (JSON)
    // Ejemplo: { roomId: '...', nicknameHash: '...', reason: 'invalid_password' }
    metadata: { type: mongoose.Schema.Types.Mixed },
    
    // Firma HMAC-SHA256 para verificar integridad del log
    // Permite detectar si alguien intentó modificar registros
    signature: { type: String, required: true },
  },
  // Agregar createdAt automáticamente, sin updatedAt
  { timestamps: true }
);

module.exports =
  mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema);
