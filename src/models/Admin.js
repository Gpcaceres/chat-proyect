const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    passwordHash: { type: String, required: true },
    passwordSalt: { type: String, required: true },
    passwordIterations: { type: Number, required: true },
    totpSecret: { type: String },
    roles: {
      type: [String],
      default: ['admin'],
      validate: {
        validator: (value) => value.every((role) => ['admin'].includes(role)),
        message: 'Rol no permitido',
      },
    },
    lastLoginAt: { type: Date },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Admin || mongoose.model('Admin', AdminSchema);
