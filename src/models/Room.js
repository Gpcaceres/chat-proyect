const mongoose = require('mongoose');

const EncryptedIdSchema = new mongoose.Schema(
  {
    iv: { type: String, required: true },
    content: { type: String, required: true },
    authTag: { type: String, required: true },
  },
  { _id: false }
);

const RoomSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, unique: true },
    encryptedId: { type: EncryptedIdSchema, required: true },
    pinHash: { type: String, required: true },
    pinSalt: { type: String, required: true },
    pinIterations: { type: Number, required: true },
    type: {
      type: String,
      enum: ['text', 'multimedia'],
      required: true,
      default: 'text',
    },
    maxFileSizeMB: { type: Number, default: 10 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    active: { type: Boolean, default: true },
    sessionKey: {
      iv: String,
      content: String,
      authTag: String,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.models.Room || mongoose.model('Room', RoomSchema);
