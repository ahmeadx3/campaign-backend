const express = require('express');
const cors = require('cors');
const { Redis } = require('@upstash/redis');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const BOT_TOKEN = process.env.BOT_TOKEN || "";

function verifyTelegramData(initData) {
  if (!initData) return null;
  const urlParams = new URLSearchParams(initData);
  const hash = urlParams.get('hash');
  urlParams.delete('hash');

  const params = [];
  for (const [key, value] of urlParams.entries()) {
    params.push(`${key}=${value}`);
  }
  params.sort();

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calculatedHash = crypto.createHmac('sha256', secretKey).update(params.join('\n')).digest('hex');

  if (calculatedHash === hash) {
    const user = JSON.parse(urlParams.get('user') || '{}');
    return user.id;
  }
  return null;
}

app.post('/api/start-session', async (req, res) => {
  const { initData } = req.body;
  const userId = verifyTelegramData(initData) || req.body.demoUserId;

  if (!userId) return res.status(401).json({ error: 'Unauthorized Telegram user' });

  const today = new Date().toISOString().split('T')[0];
  const claimed = await redis.get(`claimed:${today}:${userId}`);
  if (claimed) return res.status(400).json({ error: 'Already claimed today' });

  const sessionToken = crypto.randomBytes(16).toString('hex');
  const sessionData = { userId, startTime: Date.now(), today };

  await redis.set(`session:${sessionToken}`, JSON.stringify(sessionData), { ex: 600 });
  res.json({ ok: true, sessionToken });
});

app.get('/api/get-word', async (req, res) => {
  const { session } = req.query;
  if (!session) return res.status(400).json({ error: 'Missing session' });

  const rawSession = await redis.get(`session:${session}`);
  if (!rawSession) return res.status(400).json({ error: 'Session expired or invalid' });

  const { userId, startTime, today } = typeof rawSession === 'string' ? JSON.parse(rawSession) : rawSession;

  const elapsedSeconds = (Date.now() - startTime) / 1000;
  if (elapsedSeconds < 14.5) {
    return res.status(429).json({ error: 'Timer fast-forwarded!' });
  }

  const uniqueCode = `WORD-${userId.toString().slice(-4)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

  await redis.set(`code:${uniqueCode}`, JSON.stringify({ userId, today }), { ex: 3600 });
  res.json({ ok: true, code: uniqueCode });
});

app.post('/api/claim-word', async (req, res) => {
  const { initData, code } = req.body;
  const userId = verifyTelegramData(initData) || req.body.demoUserId;

  if (!userId) return res.status(401).json({ error: 'Unauthorized Telegram user' });

  const cleanCode = (code || '').trim().toUpperCase();
  const rawCodeData = await redis.get(`code:${cleanCode}`);

  if (!rawCodeData) {
    return res.status(400).json({ ok: false, message: 'Invalid or expired code.' });
  }

  const { userId: ownerId, today } = typeof rawCodeData === 'string' ? JSON.parse(rawCodeData) : rawCodeData;

  if (ownerId.toString() !== userId.toString()) {
    return res.status(403).json({ ok: false, message: 'This code belongs to another user!' });
  }

  const alreadyClaimed = await redis.get(`claimed:${today}:${userId}`);
  if (alreadyClaimed) {
    return res.status(400).json({ ok: false, message: 'Already claimed today.' });
  }

  await redis.set(`claimed:${today}:${userId}`, "1", { ex: 86400 * 2 });
  await redis.del(`code:${cleanCode}`);

  res.json({ ok: true, points: 3000 });
});

module.exports = app;
