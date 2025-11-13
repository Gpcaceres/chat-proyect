const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema(
  {
    action: { type: String, required: true },
    actor: { type: String, required: true },
    metadata: { type: mongoose.Schema.Types.Mixed },
    signature: { type: String, required: true },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema);
