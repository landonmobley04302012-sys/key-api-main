require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

const keySchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  game: { type: String, required: true, default: 'bee_swarm' },
  userId: { type: String },
  deviceId: { type: String },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});
const Key = mongoose.model('Key', keySchema);

const blacklistSchema = new mongoose.Schema({
  identifier: { type: String, unique: true },
  expiresAt: { type: Date, required: true }
});
const Blacklist = mongoose.model('Blacklist', blacklistSchema);

const unbindAttemptSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  lastUnbind: { type: Date, default: Date.now }
});
const UnbindAttempt = mongoose.model('UnbindAttempt', unbindAttemptSchema);

function generateKey() {
  return crypto.randomBytes(12).toString('hex').toUpperCase();
}

// === Public endpoints ===

app.post('/validate', async (req, res) => {
  const { key, deviceId } = req.body;
  if (!key || !deviceId) return res.status(400).json({ error: 'missing fields' });
  const record = await Key.findOne({ key });
  if (!record) return res.json({ valid: false, reason: 'not_found' });
  if (record.expiresAt && record.expiresAt < new Date()) {
    return res.json({ valid: false, reason: 'expired' });
  }
  if (!record.deviceId) {
    record.deviceId = deviceId;
    await record.save();
    return res.json({ valid: true, expiresAt: record.expiresAt });
  }
  if (record.deviceId !== deviceId) {
    return res.json({ valid: false, reason: 'device_mismatch' });
  }
  res.json({ valid: true, expiresAt: record.expiresAt });
});

app.post('/check', async (req, res) => {
  const { game, userId, deviceId } = req.body;
  if (!game || !userId || !deviceId) return res.status(400).json({ error: 'missing fields' });
  const record = await Key.findOne({
    $or: [
      { userId, deviceId, game },
      { deviceId, game, userId: null }
    ],
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ]
  });
  res.json({ key: record ? record.key : null });
});

app.post('/claim/:game', async (req, res) => {
  const { game } = req.params;
  const { user_id, device_id } = req.body;
  if (!user_id || !device_id) return res.status(400).json({ error: 'missing user_id or device_id' });
  const blacklisted = await Blacklist.findOne({ identifier: user_id, expiresAt: { $gt: new Date() } });
  if (blacklisted) return res.status(403).json({ error: 'blacklisted' });
  const existing = await Key.findOne({ deviceId: device_id, game, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] });
  if (existing) return res.json({ key: existing.key });
  const newKey = generateKey();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await Key.create({ key: newKey, game, userId: user_id, deviceId: device_id, expiresAt });
  res.json({ key: newKey });
});

app.get('/key-info', async (req, res) => {
  const { key } = req.query;
  if (!key) return res.status(400).json({ error: 'missing key' });
  const record = await Key.findOne({ key });
  if (!record) return res.json({ valid: false, exists: false });
  const valid = !record.expiresAt || record.expiresAt > new Date();
  res.json({
    valid,
    exists: true,
    expiresAt: record.expiresAt,
    bound: !!record.deviceId,
    game: record.game,
    userId: record.userId
  });
});

app.post('/unbind', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'missing key' });
  const record = await Key.findOne({ key });
  if (!record) return res.status(404).json({ error: 'key not found' });
  if (record.expiresAt && record.expiresAt < new Date()) {
    return res.status(400).json({ error: 'key expired' });
  }
  let attempt = await UnbindAttempt.findOne({ key });
  if (attempt && attempt.lastUnbind > new Date(Date.now() - 24 * 60 * 60 * 1000)) {
    return res.status(429).json({ error: 'You can only unbind once per 24 hours. Try again later.' });
  }
  record.deviceId = null;
  await record.save();
  if (attempt) {
    attempt.lastUnbind = new Date();
    await attempt.save();
  } else {
    await UnbindAttempt.create({ key, lastUnbind: new Date() });
  }
  res.json({ success: true, message: 'Key unbound. You can now use it on a new device.' });
});

// === Admin endpoints ===
app.post('/admin/create', async (req, res) => {
  const { secret, game, duration_days, userId, deviceId } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  const expiresAt = duration_days ? new Date(Date.now() + duration_days * 24 * 60 * 60 * 1000) : null;
  const newKey = generateKey();
  await Key.create({ key: newKey, game, userId, deviceId, expiresAt });
  res.json({ key: newKey });
});

app.post('/admin/blacklist', async (req, res) => {
  const { secret, identifier, hours } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
  await Blacklist.findOneAndUpdate({ identifier }, { expiresAt }, { upsert: true });
  res.json({ success: true });
});

app.post('/admin/list-keys', async (req, res) => {
  const { secret } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  const keys = await Key.find({}, { key: 0 }); // exclude the key field
  res.json(keys);
});

app.post('/admin/unbind', async (req, res) => {
  const { secret, key } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  const record = await Key.findOne({ key });
  if (!record) return res.status(404).json({ error: 'key not found' });
  record.deviceId = null;
  await record.save();
  res.json({ success: true, message: 'Key unbound by admin.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
