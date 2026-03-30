require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.get('/test', (req, res) => res.json({ status: 'ok' }));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// ========== Schemas ==========
const keySchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  game: { type: String, required: true, default: 'mobscripts' },
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

const pendingClaimSchema = new mongoose.Schema({
  code: { type: String, unique: true, required: true },
  userId: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 } // auto‑delete after 1 hour
});
const PendingClaim = mongoose.model('PendingClaim', pendingClaimSchema);

function generateKey() {
  return crypto.randomBytes(12).toString('hex').toUpperCase();
}

// ========== Public endpoints ==========
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
  const existing = await Key.findOne({ userId: user_id, game, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] });
  if (existing) return res.json({ key: existing.key });
  const newKey = generateKey();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await Key.create({ key: newKey, game, userId: user_id, deviceId: device_id, expiresAt });
  res.json({ key: newKey });
});

app.get('/user-key/:userId', async (req, res) => {
  const { userId } = req.params;
  const record = await Key.findOne({
    userId,
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ]
  });
  res.json({ key: record ? record.key : null });
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
    claimed: !!record.userId,
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

app.post('/redeem', async (req, res) => {
  const { key, discordId } = req.body;
  if (!key || !discordId) return res.status(400).json({ error: 'missing fields' });
  const record = await Key.findOne({ key });
  if (!record) return res.status(404).json({ error: 'Key not found' });
  if (record.expiresAt && record.expiresAt < new Date()) {
    return res.status(400).json({ error: 'Key expired' });
  }
  if (record.userId) {
    return res.status(400).json({ error: 'Key already claimed' });
  }
  record.userId = discordId;
  await record.save();
  res.json({ success: true, message: 'Key claimed successfully!' });
});

app.post('/reset-hwid', async (req, res) => {
  const { key, discordId } = req.body;
  if (!key || !discordId) return res.status(400).json({ error: 'missing fields' });
  const record = await Key.findOne({ key });
  if (!record) return res.status(404).json({ error: 'Key not found' });
  if (record.userId !== discordId) {
    return res.status(403).json({ error: 'This key does not belong to you' });
  }
  if (record.expiresAt && record.expiresAt < new Date()) {
    return res.status(400).json({ error: 'Key expired' });
  }
  record.deviceId = null;
  await record.save();
  res.json({ success: true, message: 'HWID reset. Next time you run the script, it will bind to your new device.' });
});

app.post('/claim-with-code', async (req, res) => {
  const { code, device_id } = req.body;
  if (!code || !device_id) return res.status(400).json({ error: 'missing code or device_id' });
  const pending = await PendingClaim.findOne({ code });
  if (!pending) return res.status(404).json({ error: 'Invalid or expired code' });
  const userId = pending.userId;
  const game = 'mobscripts';

  const existing = await Key.findOne({ userId, game, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] });
  if (existing) {
    await PendingClaim.deleteOne({ code });
    return res.json({ key: existing.key });
  }

  const newKey = generateKey();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await Key.create({ key: newKey, game, userId, deviceId: device_id, expiresAt });
  await PendingClaim.deleteOne({ code });
  res.json({ key: newKey });
});

// ========== Admin endpoints ==========
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
  const keys = await Key.find({}, { key: 0 });
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

app.post('/admin/removekey', async (req, res) => {
  const { secret, userId } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  if (!userId) return res.status(400).json({ error: 'missing userId' });
  const result = await Key.deleteMany({ userId });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'No key found for that user' });
  res.json({ success: true, deleted: result.deletedCount });
});

app.post('/admin/keys', async (req, res) => {
  const { secret, type, userId } = req.body;
  if (secret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: 'unauthorized' });
  let filter = {};
  if (type === 'perm') filter.expiresAt = null;
  if (type === 'timed') filter.expiresAt = { $ne: null };
  if (userId) filter.userId = userId;
  const keys = await Key.find(filter, { key: 0 });
  res.json(keys);
});

app.post('/admin/pending-claim', async (req, res) => {
  const { code, userId } = req.body;
  if (!code || !userId) return res.status(400).json({ error: 'missing code or userId' });
  await PendingClaim.create({ code, userId });
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
