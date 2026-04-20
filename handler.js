const { S3Client, GetObjectCommand, PutObjectCommand, HeadObjectCommand, DeleteObjectCommand, CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const crypto = require('crypto');

// ─── NEW MEDIACONVERT IMPORTS ─────────────────────────────────────────────────
const { MediaConvertClient, CreateJobCommand } = require("@aws-sdk/client-mediaconvert");

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const AWS_REGION = process.env.S3_REGION         || 'eu-west-1';
const BUCKET     = process.env.AWS_S3_BUCKET;
const CF_DOMAIN  = process.env.AWS_CLOUDFRONT_DOMAIN || 'dvy39dvzad781.cloudfront.net';
const JWT_SECRET = process.env.JWT_SECRET        || 'playonce-jwt-secret-change-in-prod';

// --- MEDIACONVERT CONFIG ---
const MEDIACONVERT_ENDPOINT = process.env.MEDIACONVERT_ENDPOINT; // e.g., https://xxxxx.mediaconvert.eu-west-1.amazonaws.com
const MEDIACONVERT_ROLE_ARN = process.env.MEDIACONVERT_ROLE_ARN; // IAM Role for MediaConvert

const s3 = new S3Client({ region: AWS_REGION });
// Initialize MediaConvert client (only if endpoint is provided in env vars)
const mcClient = MEDIACONVERT_ENDPOINT ? new MediaConvertClient({ region: AWS_REGION, endpoint: MEDIACONVERT_ENDPOINT }) : null;

// ─── PASSWORD HASHING ─────────────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash('sha256').update('playonce:' + password).digest('hex');
}

// ─── JWT ──────────────────────────────────────────────────────────────────────
function signJWT(payload) {
  const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body    = Buffer.from(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + 30*24*60*60*1000 })).toString('base64url');
  const sig     = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest('base64url');
  return header + '.' + body + '.' + sig;
}
function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

// ─── S3 USER STORAGE ──────────────────────────────────────────────────────────
const _creatorCache = new Map();
const _creatorCacheTTL = 5000; // 5 second in-memory cache per Lambda instance
async function getCreator(username) {
  const key = username.toLowerCase();
  const cached = _creatorCache.get(key);
  if (cached && Date.now() - cached.ts < _creatorCacheTTL) return cached.data;
  try {
    const r = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'data/users/' + key + '.json' }));
    const data = JSON.parse(await r.Body.transformToString());
    _creatorCache.set(key, { data, ts: Date.now() });
    return data;
  } catch(e) { return null; }
}
async function putCreator(creator) {
  const key = creator.username.toLowerCase();
  await withLock('creator:' + key, async () => {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET, Key: 'data/users/' + key + '.json',
      Body: JSON.stringify(creator), ContentType: 'application/json',
    }));
    _creatorCache.delete(key);
  });
}

// ─── USER INDEX ───────────────────────────────────────────────────────────────
let _index = null, _indexAge = 0;
async function getUserIndex() {
  if (_index && (Date.now() - _indexAge) < 30000) return _index;
  try {
    const r = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'data/user-index.json' }));
    _index = JSON.parse(await r.Body.transformToString());
    _indexAge = Date.now();
    return _index;
  } catch(e) { return []; }
}
async function addToIndex(username, email, extra = {}) {
  const idx = await getUserIndex();
  const existing = idx.find(u => u.username === username);
  if (!existing) {
    idx.push({ username, email, ...extra });
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: 'data/user-index.json', Body: JSON.stringify(idx), ContentType: 'application/json' }));
    _index = idx; _indexAge = Date.now();
  } else if (extra && Object.keys(extra).length) {
    // Update existing entry with new fields (e.g. verified status change)
    Object.assign(existing, extra);
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: 'data/user-index.json', Body: JSON.stringify(idx), ContentType: 'application/json' }));
    _index = idx; _indexAge = Date.now();
  }
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
async function authUser(username, password) {
  if (!username || !password) return null;
  const c = await getCreator(username.toLowerCase());
  if (!c) return null;
  const hashed = hashPassword(password);
  // Support legacy plaintext AND new hashed passwords
  if (c.passwordHash === hashed || c.passwordHash === password) {
    // Migrate plaintext to hash on successful login
    if (c.passwordHash === password) {
      c.passwordHash = hashed;
      await putCreator(c);
    }
    return c;
  }
  return null;
}
async function authJWT(token) {
  if (!token) return null;
  const payload = verifyJWT(token.replace('Bearer ', ''));
  if (!payload) return null;
  return await getCreator(payload.username);
}
function getToken(event) {
  const hdrs = event.headers || {};
  // REST API uses mixed case; HTTP API uses lowercase — check both
  const auth = hdrs['Authorization'] || hdrs['authorization'] || '';
  const tok  = auth.replace(/^Bearer\s+/i, '').trim();
  return tok || null;
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function pub(c) {
  if (!c) return null;
  const { passwordHash, ...p } = c;
  const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  // Filter expired drops from public view — expired drops vanish regardless of copyright status
  if (p.drops) {
    // Public vault — hide copyright-held drops from viewers
    p.drops = p.drops.filter(d => {
      if (d.copyrightHold) return false;
      const start = (d.scheduledAt && d.scheduledAt > (d.uploadedAt||0)) ? d.scheduledAt : (d.uploadedAt||0);
      if (!start) return true;
      return (now - start) < THREE_DAYS_MS;
    });
  }
  if (p.creatorDrops) {
    // Creator Content Manager — keep copyright-held drops so creator sees the notice
    // Only filter truly expired drops
    p.creatorDrops = p.creatorDrops.filter(d => {
      const start = (d.scheduledAt && d.scheduledAt > (d.uploadedAt||0)) ? d.scheduledAt : (d.uploadedAt||0);
      if (!start) return true;
      return (now - start) < THREE_DAYS_MS; // copyrightHold drops are intentionally kept
    });
  }
  return p;
}
// ── Rate limiting — in-memory per Lambda instance ────────────────────────────
const _rateLimitMap = new Map(); // key -> { count, resetAt }
function rateLimit(key, maxPerMinute) {
  const now = Date.now();
  const entry = _rateLimitMap.get(key) || { count: 0, resetAt: now + 60000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 60000; }
  entry.count++;
  _rateLimitMap.set(key, entry);
  // Clean up old entries every 1000 checks
  if (_rateLimitMap.size > 1000) {
    for (const [k, v] of _rateLimitMap) { if (now > v.resetAt) _rateLimitMap.delete(k); }
  }
  return entry.count > maxPerMinute;
}

// ── S3 write mutex — prevents concurrent overwrites of same creator file ────
const _writeLocks = new Map();
async function withLock(key, fn) {
  while (_writeLocks.get(key)) await new Promise(r => setTimeout(r, 50));
  _writeLocks.set(key, true);
  try { return await fn(); } finally { _writeLocks.delete(key); }
}

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,x-admin-key',
  'Access-Control-Max-Age': '86400',
};
const ok  = b => ({ statusCode: 200, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
const err = (c, m) => ({ statusCode: c, headers: { ...CORS, 'Content-Type': 'application/json' }, body: JSON.stringify({ error: m }) });

function extFromMime(mime) {
  if (!mime) return '.mp4';
  if (mime.startsWith('audio/')) return '.mp3';
  if (mime.includes('webm'))     return '.webm';
  if (mime.includes('ogg'))      return '.ogg';
  if (mime.includes('quicktime') || mime.includes('mov')) return '.mov';
  return '.mp4';
}

// ─── FREE EMAIL DOMAINS ───────────────────────────────────────────────────────
// ── Platform notifications — Slack webhook + admin email ─────────────────────
async function notify(subject, text, emoji = '🔔') {
  const SLACK_URL   = process.env.SLACK_WEBHOOK_URL;
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.SES_FROM_EMAIL;
  const ADMIN_URL   = process.env.ADMIN_URL || 'https://main.daiw44z798u76.amplifyapp.com/admin.html';

  // Slack
  if (SLACK_URL) {
    try {
      const slackLines = text.split('\n').map(l => l.trim()).filter(Boolean).join('\n');
      const slackBody = JSON.stringify({
        text: emoji + ' *' + subject + '*\n' + slackLines + '\n<' + ADMIN_URL + '|Open Admin Panel>'
      });
      const https = require('https');
      const url = new URL(SLACK_URL);
      await new Promise((res, rej) => {
        const req = https.request({
          hostname: url.hostname, path: url.pathname + url.search,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(slackBody) }
        }, r => { r.on('data', () => {}); r.on('end', res); });
        req.on('error', rej); req.write(slackBody); req.end();
      });
    } catch(e) { console.warn('Slack notify failed:', e.message); }
  }

  // Email
  if (ADMIN_EMAIL) {
    try {
      await sendEmail(ADMIN_EMAIL, subject, text + '\n\nAdmin panel: ' + ADMIN_URL);
    } catch(e) { console.warn('Email notify failed:', e.message); }
  }
}

const FREE_EMAIL_DOMAINS = new Set(['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','live.com','msn.com','aol.com','protonmail.com','pm.me','ymail.com','mail.com','inbox.com','zoho.com','tutanota.com','yahoo.co.uk','yahoo.co.ke','yahoo.com.ng','hotmail.co.uk','googlemail.com','me.com','mac.com']);
function isFreeEmailDomain(email) { return FREE_EMAIL_DOMAINS.has((email||'').split('@')[1]?.toLowerCase()||''); }

// ─── SES EMAIL ────────────────────────────────────────────────────────────────
async function sendEmail(to, subject, body) {
  // Try Resend first (instant approval, works immediately)
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (RESEND_KEY) {
    try {
      const https = require('https');
      const payload = JSON.stringify({
        from: 'PlayOnce <support@playonce.app>',
        to: [to],
        subject,
        text: body,
      });
      await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.resend.com',
          path: '/emails',
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + RESEND_KEY,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          }
        }, res => {
          let data = '';
          res.on('data', c => data += c);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
            else reject(new Error('Resend error ' + res.statusCode + ': ' + data));
          });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
      });
      return; // Resend succeeded — done
    } catch(e) {
      console.warn('Resend failed:', e.message, '— falling back to SES');
    }
  }

  // Fallback to SES
  const FROM = process.env.SES_FROM_EMAIL;
  if (!FROM) {
    console.warn('No email provider configured (RESEND_API_KEY or SES_FROM_EMAIL missing) — email not sent to', to);
    return;
  }
  const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
  const ses = new SESClient({ region: AWS_REGION });
  await ses.send(new SendEmailCommand({
    Source: FROM,
    Destination: { ToAddresses: [to] },
    Message: { Subject: { Data: subject }, Body: { Text: { Data: body } } }
  }));
}

// ─── MEDIACONVERT — Adaptive Bitrate HLS (NEW SDK) ─────────────────────────────
async function triggerMediaConvert(inputKey, username, dropId) {
  if (!mcClient || !MEDIACONVERT_ROLE_ARN) {
    console.warn("MediaConvert not configured (missing Endpoint or Role ARN). Skipping HLS generation.");
    return;
  }

  const inputS3Url = `s3://${BUCKET}/${inputKey}`;
  const outputS3Prefix = `s3://${BUCKET}/hls/${username}/${dropId}/`;

  // Define the 4 quality levels
  const videoOutputs = [
    { name: '1080p', height: 1080, width: 1920, bitrate: 5000000 },
    { name: '720p',  height: 720,  width: 1280, bitrate: 3000000 },
    { name: '480p',  height: 480,  width: 854,  bitrate: 1500000 },
    { name: '360p',  height: 360,  width: 640,  bitrate: 800000  }
  ].map(q => ({
    NameModifier: `_${q.name}`,
    ContainerSettings: { Container: "M3U8" },
    VideoDescription: {
      Width: q.width, Height: q.height,
      CodecSettings: {
        Codec: "H_264",
        H264Settings: { Bitrate: q.bitrate, RateControlMode: "CBR", QualityTuningLevel: "SINGLE_PASS" }
      }
    }
  }));

  // Add Audio-only stream
  const audioOutput = {
    NameModifier: "_audio",
    ContainerSettings: { Container: "M3U8" },
    AudioDescriptions: [{ AudioSourceName: "Audio Selector 1", CodecSettings: { Codec: "AAC", AacSettings: { Bitrate: 96000, CodingProfile: "LC", SampleRate: 48000 } } }]
  };

  const params = {
    Role: MEDIACONVERT_ROLE_ARN,
    Settings: {
      Inputs: [{ FileInput: inputS3Url, AudioSelectors: { "Audio Selector 1": { DefaultSelection: "DEFAULT" } } }],
      OutputGroups: [{
        Name: "Apple HLS",
        OutputGroupSettings: {
          Type: "HLS_GROUP_SETTINGS",
          HlsGroupSettings: {
            Destination: outputS3Prefix,
            SegmentLength: 4,
            MinSegmentLength: 0,
            DirectoryStructure: "SINGLE_DIRECTORY",
            ManifestDurationFormat: "INTEGER"
          }
        },
        Outputs: [audioOutput, ...videoOutputs]
      }]
    }
  };

  try {
    await mcClient.send(new CreateJobCommand(params));
    console.log(`MediaConvert job started successfully for ${dropId}`);
  } catch (err) {
    console.error("Error starting MediaConvert job:", err);
  }
}

// ─── S3 TRIGGER ───────────────────────────────────────────────────────────────
async function handleS3Event(event) {
  for (const record of event.Records) {
    const key      = decodeURIComponent(record.s3.object.key.replace(/\+/g, ' '));
    const parts    = key.split('/');
    if (parts.length !== 3 || parts[0] !== 'drops') continue;
    const username = parts[1];
    const dropId   = parts[2].replace(/\.[^.]+$/, '');
    const fileUrl  = 'https://' + CF_DOMAIN + '/' + key;
    console.log('S3 trigger: saving mediaUrl for', username, dropId);
    try {
      const creator = await getCreator(username);
      if (!creator) continue;
      if (!Array.isArray(creator.drops))        creator.drops        = [];
      if (!Array.isArray(creator.creatorDrops)) creator.creatorDrops = [];
      let drop  = creator.drops.find(d => String(d.id) === String(dropId));
      let cdrop = creator.creatorDrops.find(d => String(d.id) === String(dropId));
      // Only update mediaUrl — never recreate a drop that doesn't exist
      // (creator may have deleted it; S3 file still exists but drop should stay deleted)
      if (!drop && !cdrop) { console.log('S3 trigger: drop not found in creator profile — skipping (may have been deleted):', dropId); continue; }
      if (drop)  { drop.mediaUrl  = fileUrl; }
      if (cdrop) { cdrop.mediaUrl = fileUrl; }
      await putCreator(creator);
      // Trigger MediaConvert from S3 backup trigger
      await triggerMediaConvert(key, username, dropId);
    } catch(e) { console.error('S3 trigger error:', e.message); }
  }
}

// ─── STRIPE ───────────────────────────────────────────────────────────────────
async function stripeRequest(method, path, params) {
  const https = require('https');
  const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || '';
  const body = params ? new URLSearchParams(params).toString() : '';
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: 'api.stripe.com', path, method, headers: { 'Authorization': 'Bearer ' + STRIPE_SECRET, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve({ _raw: data }); } });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// stripeRequestRaw — accepts a pre-encoded body string (for arrays/nested objects)
async function stripeRequestRaw(method, path, body) {
  const https = require('https');
  const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || '';
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: 'api.stripe.com', path, method, headers: { 'Authorization': 'Bearer ' + STRIPE_SECRET, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body || '') } }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve({ _raw: data }); } });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.Records && event.Records[0]?.eventSource === 'aws:s3') {
    await handleS3Event(event);
    return { statusCode: 200, body: 'ok' };
  }

  const method = event.httpMethod || event.requestContext?.http?.method || 'GET';
  const path   = event.path || event.rawPath || '/';
  const qs     = event.queryStringParameters || {};
  let   body   = {};

  if (method === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };
  try { body = JSON.parse(event.body || '{}'); } catch(e) {}

  // ── GET /api/creators/index — lightweight name list for instant search ────────
  if (method === 'GET' && path === '/api/creators/index') {
    const idx = await getUserIndex();
    // Return only what's needed for instant filtering — no per-creator S3 reads
    return ok(idx.map(u => ({ username: u.username, displayName: u.displayName || null, verified: u.verified || false })));
  }

  // ── GET /api/search ──────────────────────────────────────────────────────────
  if (method === 'GET' && path === '/api/search') {
    const q = (qs.q || '').toLowerCase().trim();
    if (!q) return ok([]);
    const idx = await getUserIndex();
    // Score: 2 = startsWith (best), 1 = includes (fallback)
    const scored = idx
      .map(u => {
        const n = u.username.toLowerCase(); const d = (u.displayName||'').toLowerCase();
        const score = (n.startsWith(q) || d.startsWith(q)) ? 2 : (n.includes(q) || d.includes(q)) ? 1 : 0;
        return { u, score };
      })
      .filter(x => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 8);
    const results = await Promise.all(scored.map(async ({ u }) => {
      const c = await getCreator(u.username);
      return c ? pub(c) : null;
    }));
    return ok(results.filter(c => c && !c.banned));
  }

  // ── GET /api/creator/:username ───────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/api/creator/')) {
    const username = decodeURIComponent(path.split('/api/creator/')[1]);
    const c = await getCreator(username.toLowerCase());
    if (!c) return err(404, 'NOT FOUND');
    if (c.banned) return err(404, 'NOT FOUND'); // banned creators are invisible
    return ok(pub(c));
  }

  // ── POST /api/auth/signup ────────────────────────────────────────────────────
  if (method === 'POST' && path === '/api/auth/signup') {
    const ip = event.requestContext?.identity?.sourceIp || event.requestContext?.http?.sourceIp || 'unknown';
    if (rateLimit('signup:' + ip, 3)) return err(429, 'Too many signup attempts. Try again in a minute.');
    const { username, email, password } = body;
    if (!username || !email || !password) return err(400, 'ALL FIELDS REQUIRED');
    if (!/^[a-z0-9_]{3,20}$/.test(username)) return err(400, 'USERNAME: 3-20 CHARS, LETTERS/NUMBERS/_ ONLY');
    const existing = await getCreator(username);
    if (existing) return err(400, 'USERNAME ALREADY TAKEN');
    const creator = { username, email, passwordHash: hashPassword(password), drops: [], creatorDrops: [], grossRevenue: 0, paidViews: 0, refundRequests: [], createdAt: Date.now() };
    await putCreator(creator);
    await addToIndex(username, email);
    const token = signJWT({ username });
    notify('New creator signup', `@${username}\nEmail: ${email}`, '🎉').catch(() => {});
    // Send welcome email
    sendEmail(email,
      'Welcome to PlayOnce — @' + username,
      'Hi @' + username + ',\n\nWelcome to PlayOnce! Your account is ready.\n\nStart by uploading your first drop — it will be live for 3 days for your fans to watch.\n\nYour profile: https://playonce.app\n\nIf you have any questions, reply to this email.\n\nPlayOnce Support\nsupport@playonce.app'
    ).catch(e => console.warn('Welcome email failed:', e.message));
    return ok({ status: 'ok', token, creator: pub(creator) });
  }

  // ── GET /api/auth/status — check own account status (works even if banned) ─────
  if (method === 'GET' && path === '/api/auth/status') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    return ok({
      username: creator.username,
      banned: creator.banned || false,
      bannedReason: creator.bannedReason || null,
      payoutsFrozen: creator.payoutsFrozen || false,
      strikes: (creator.strikes || []).length,
    });
  }

  // ── POST /api/auth/login ─────────────────────────────────────────────────────
  if (method === 'POST' && path === '/api/auth/login') {
    const ip = event.requestContext?.identity?.sourceIp || event.requestContext?.http?.sourceIp || 'unknown';
    if (rateLimit('login:' + ip, 10)) return err(429, 'Too many login attempts. Try again in a minute.');
    const { username, password } = body;
    const c = await authUser(username, password);
    if (!c) return err(401, 'INCORRECT USERNAME OR PASSWORD');
    if (c.banned) return err(403, 'ACCOUNT BANNED. Contact ' + (process.env.SUPPORT_EMAIL || process.env.ADMIN_EMAIL || 'support@playonce.app') + ' to appeal.');
    const token = signJWT({ username: c.username });
    return ok({ status: 'ok', token, creator: pub(c) });
  }

  // ── All routes below require JWT auth ─────────────────────────────────────
  // Try JWT first, fall back to password for backward compat
  async function getAuth() {
    const token = getToken(event);
    if (token) {
      const c = await authJWT(token);
      if (c) return c;
      console.warn('JWT auth failed for path:', path);
    }
    // Fallback: password in body or query string (backward compat)
    const u = body.username || qs.username;
    const p = body.password || qs.password;
    if (u && p) return await authUser(u, p);
    return null;
  }

  // ── GET /api/auth/status — check own account status (works even if banned) ─────
  if (method === 'GET' && path === '/api/auth/status') {
    const creatorStatus = await getAuth();
    if (!creatorStatus) return err(401, 'UNAUTHORIZED');
    return ok({
      username: creatorStatus.username,
      banned: creatorStatus.banned || false,
      bannedReason: creatorStatus.bannedReason || null,
      payoutsFrozen: creatorStatus.payoutsFrozen || false,
      strikes: (creatorStatus.strikes || []).length,
    });
  }

  // ── POST /api/creator/save ───────────────────────────────────────────────────
  if (method === 'POST' && path === '/api/creator/save') {
    const creator = await getAuth();
    if (!creator) {
      console.warn('save UNAUTHORIZED — token:', !!getToken(event), 'username:', body.username || body.data?.username);
      return err(401, 'UNAUTHORIZED');
    }
    console.log('save OK for', creator.username, '— drops:', (body.data||body)?.drops?.length);
    // data can be in body.data OR body itself (handle both formats)
    const data = body.data || body;
    let updated = { ...creator, ...data, username: creator.username, passwordHash: creator.passwordHash };
    if (Array.isArray(data?.drops) && Array.isArray(creator.drops)) {
      updated.drops = data.drops.map(nd => {
        const ex = creator.drops.find(d => String(d.id) === String(nd.id));
        return (ex && ex.mediaUrl && !nd.mediaUrl) ? { ...nd, mediaUrl: ex.mediaUrl } : nd;
      });
    }
    if (Array.isArray(data?.creatorDrops) && Array.isArray(creator.creatorDrops)) {
      updated.creatorDrops = data.creatorDrops.map(nd => {
        const ex = creator.creatorDrops.find(d => String(d.id) === String(nd.id));
        return (ex && ex.mediaUrl && !nd.mediaUrl) ? { ...nd, mediaUrl: ex.mediaUrl } : nd;
      });
    }
    await putCreator(updated);
    return ok({ status: 'ok' });
  }

  // ── POST /creator/autopublish ─────────────────────────────────────────────────
  if (method === 'POST' && path === '/creator/autopublish') {
    const { username } = body;
    const creator = await getCreator(username);
    if (!creator) return ok({ status: 'ok' });
    const now = Date.now();
    let changed = false;
    (creator.drops || []).forEach(d => { if (d.scheduledAt && d.scheduledAt <= now && !d.live) { d.live = true; changed = true; } });
    (creator.creatorDrops || []).forEach(d => { if (d.scheduledAt && d.scheduledAt <= now && !d.live) { d.live = true; changed = true; } });
    if (changed) await putCreator(creator);
    return ok({ status: 'ok' });
  }

  // ── GET /media/signed-video — time-limited CloudFront signed URL for video ────
  if (method === 'GET' && path === '/media/signed-video') {
    const { username, dropId } = qs;
    if (!username || !dropId) return err(400, 'Missing params');
    const creator = await getCreator(username.toLowerCase());
    if (!creator) return err(404, 'Not found');
    const drop = (creator.drops || []).find(d => String(d.id) === String(dropId));
    if (!drop || !drop.mediaUrl) return err(404, 'Drop not found');
    if (!drop.live) return err(403, 'Drop not available');

    const CF_KEY_ID  = process.env.CF_PRIVATE_KEY_ID;
    let   CF_KEY_PEM = process.env.CF_PRIVATE_KEY || '';

    // If CF signing not configured — return plain URL (backward compatible)
    if (!CF_KEY_ID || !CF_KEY_PEM) {
      return ok({ url: drop.mediaUrl, hlsUrl: drop.hlsUrl || null, signed: false });
    }

    try {
      const crypto = require('crypto');
      // Lambda env vars replace newlines with \n literal — restore them
      CF_KEY_PEM = CF_KEY_PEM.replace(/\\n/g, '\n');

      const expires = Math.floor(Date.now() / 1000) + 4 * 3600; // 4 hour window

      // Use wildcard custom policy — covers video file AND all HLS segments
      function signWildcard(baseUrl) {
        // Strip filename, use directory wildcard
        const dir = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1) + '*';
        const policyStr = JSON.stringify({
          Statement: [{
            Resource: dir,
            Condition: { DateLessThan: { 'AWS:EpochTime': expires } }
          }]
        });
        const policyB64 = Buffer.from(policyStr).toString('base64')
          .replace(/\+/g, '-').replace(/\//g, '~').replace(/=/g, '_');
        const signer = crypto.createSign('RSA-SHA1');
        signer.update(policyStr);
        const sig = signer.sign(CF_KEY_PEM, 'base64')
          .replace(/\+/g, '-').replace(/\//g, '~').replace(/=/g, '_');
        return '?Policy=' + policyB64 + '&Signature=' + sig + '&Key-Pair-Id=' + CF_KEY_ID;
      }

      const queryString = signWildcard(drop.mediaUrl);
      const signedMp4   = drop.mediaUrl + queryString;
      const signedHls   = drop.hlsUrl   ? drop.hlsUrl + queryString : null;
      // Thumbnails are public (separate CF behavior) — no signing needed
      const signedThumb = drop.thumbnailUrl || null;

      return ok({ url: signedMp4, hlsUrl: signedHls, thumbUrl: signedThumb, signed: true, expires });
    } catch(e) {
      console.error('CF signing failed:', e.message, '— key length:', CF_KEY_PEM.length, '— key starts:', CF_KEY_PEM.slice(0, 30));
      // Fall back to unsigned — video still works if CF restriction not yet enabled
      return ok({ url: drop.mediaUrl, hlsUrl: drop.hlsUrl || null, signed: false });
    }
  }

  // ── GET /media/sign-avatar — signed URL to upload creator profile photo ────────
  if (method === 'GET' && path === '/media/sign-avatar') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const mime = 'image/jpeg';
    const key  = 'avatars/' + creator.username + '.jpg';
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: mime }), { expiresIn: 3600 });
    const fileUrl = 'https://' + CF_DOMAIN + '/' + key;
    return ok({ uploadUrl, fileUrl });
  }

  // ── POST /media/save-avatar — persist avatar URL on creator record ────────────
  if (method === 'POST' && path === '/media/save-avatar') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { url } = body;
    if (!url) return err(400, 'url required');
    creator.avatarUrl = url;
    await putCreator(creator);
    return ok({ status: 'ok', url });
  }

  // ── GET /media/sign-thumbnail — signed URL to upload a drop thumbnail ──────────
  if (method === 'GET' && path === '/media/sign-thumbnail') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { dropId } = qs;
    if (!dropId) return err(400, 'dropId required');
    const mime = 'image/jpeg';
    const key  = 'thumbnails/' + creator.username + '/' + dropId + '.jpg';
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: mime }), { expiresIn: 3600 });
    const fileUrl = 'https://' + CF_DOMAIN + '/' + key;
    return ok({ uploadUrl, fileUrl });
  }

  // ── GET /media/sign-upload ────────────────────────────────────────────────────
  if (method === 'GET' && path === '/media/sign-upload') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { dropId, contentType } = qs;
    if (!dropId) return err(400, 'dropId required');
    const mime = decodeURIComponent(contentType || 'video/mp4');
    const ext  = extFromMime(mime);
    const key  = 'drops/' + creator.username + '/' + dropId + ext;
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: mime }), { expiresIn: 14400 });
    const fileUrl = 'https://' + CF_DOMAIN + '/' + key;
    return ok({ uploadUrl, fileUrl, key });
  }

  // ── POST /media/confirm-upload ────────────────────────────────────────────────
  if (method === 'POST' && path === '/media/confirm-upload') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { dropId, url, thumbnailUrl, title, price, currency, duration, uploadedAt, scheduledAt } = body;
    if (!dropId || !url) return err(400, 'dropId and url required');
    if (!Array.isArray(creator.drops))        creator.drops        = [];
    if (!Array.isArray(creator.creatorDrops)) creator.creatorDrops = [];
    let drop  = creator.drops.find(d => String(d.id) === String(dropId));
    let cdrop = creator.creatorDrops.find(d => String(d.id) === String(dropId));
    // If drop not found (saveCreators race condition) — create it now with full metadata
    const isScheduledDrop = scheduledAt && Number(scheduledAt) > Date.now();
    const fallback = {
      id: Number(dropId)||dropId,
      title: title || 'Untitled',
      price: parseFloat(price) || 0,
      currency: currency || 'USD',
      duration: duration || null,
      uploadedAt: uploadedAt || Date.now(),
      scheduledAt: scheduledAt ? Number(scheduledAt) : null,
      live: !isScheduledDrop, // scheduled drops start as NOT live
    };
    if (!drop)  { drop  = { ...fallback }; creator.drops.push(drop); }
    if (!cdrop) { cdrop = { ...fallback, views: 0 }; creator.creatorDrops.unshift(cdrop); }
    const _isScheduled = (drop.scheduledAt || cdrop.scheduledAt) && Number(drop.scheduledAt || cdrop.scheduledAt) > Date.now();
    drop.mediaUrl  = url; drop.live  = !_isScheduled; delete drop._uploading;  if (thumbnailUrl) drop.thumbnailUrl  = thumbnailUrl;
    cdrop.mediaUrl = url; cdrop.live = !_isScheduled; delete cdrop._uploading; if (thumbnailUrl) cdrop.thumbnailUrl = thumbnailUrl;
    await putCreator(creator);
    
    // Trigger HLS transcode using the new SDK method
    try {
      const urlObj = new URL(url);
      const inputKey = urlObj.pathname.substring(1); 
      console.log('confirm-upload: triggering MediaConvert for', creator.username, dropId, inputKey);
      await triggerMediaConvert(inputKey, creator.username, dropId);
    } catch (e) {
      console.error("Failed to parse URL for MediaConvert:", e);
    }
    
    return ok({ status: 'ok', url });
  }

  // ── GET /media/hls-status ─────────────────────────────────────────────────────
  if (method === 'GET' && path === '/media/hls-status') {
    const { username, dropId } = qs;
    if (!username || !dropId) return err(400, 'Missing parameters');

    const masterPlaylistKey = `hls/${username}/${dropId}/.m3u8`; 

    try {
      await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: masterPlaylistKey }));
      const hlsUrl = `https://${CF_DOMAIN}/${masterPlaylistKey}`;
      return ok({ ready: true, hlsUrl: hlsUrl });
    } catch (e) {
      if (e.name === 'NotFound' || e.$metadata?.httpStatusCode === 404) {
        return ok({ ready: false, processing: true });
      }
      return ok({ ready: false, processing: false, error: e.message });
    }
  }

  // ── GET /media/recover/:dropId ────────────────────────────────────────────────
  if (method === 'GET' && path.startsWith('/media/recover/')) {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const dropId = path.split('/media/recover/')[1];
    for (const ext of ['.mp4', '.webm', '.mp3', '.mov', '.ogg']) {
      const key = 'drops/' + creator.username + '/' + dropId + ext;
      try {
        await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: key }));
        const url = 'https://' + CF_DOMAIN + '/' + key;
        if (!Array.isArray(creator.drops)) creator.drops = [];
        if (!Array.isArray(creator.creatorDrops)) creator.creatorDrops = [];
        let drop  = creator.drops.find(d => String(d.id) === String(dropId));
        let cdrop = creator.creatorDrops.find(d => String(d.id) === String(dropId));
        if (!drop)  { drop  = { id: Number(dropId)||dropId, uploadedAt: Date.now(), live: true }; creator.drops.push(drop); }
        if (!cdrop) { cdrop = { id: Number(dropId)||dropId, uploadedAt: Date.now(), live: true }; creator.creatorDrops.unshift(cdrop); }
        drop.mediaUrl = url; cdrop.mediaUrl = url;
        await putCreator(creator);
        return ok({ status: 'ok', url });
      } catch(e) {}
    }
    return ok({ status: 'not_found' });
  }

  // ── POST /media/multipart/start ───────────────────────────────────────────────
  if (method === 'POST' && path === '/media/multipart/start') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { dropId, contentType } = body;
    const mime = contentType || 'video/mp4';
    const ext  = extFromMime(mime);
    const key  = 'drops/' + creator.username + '/' + dropId + ext;
    const res  = await s3.send(new CreateMultipartUploadCommand({ Bucket: BUCKET, Key: key, ContentType: mime }));
    const fileUrl = 'https://' + CF_DOMAIN + '/' + key;
    return ok({ uploadId: res.UploadId, key, fileUrl });
  }

  // ── POST /media/multipart/sign-part ──────────────────────────────────────────
  if (method === 'POST' && path === '/media/multipart/sign-part') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { key, uploadId, partNumber } = body;
    const url = await getSignedUrl(s3, new UploadPartCommand({ Bucket: BUCKET, Key: key, UploadId: uploadId, PartNumber: partNumber }), { expiresIn: 3600 });
    return ok({ url });
  }

  // ── POST /media/multipart/complete ────────────────────────────────────────────
  if (method === 'POST' && path === '/media/multipart/complete') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { key, uploadId, parts } = body;
    await s3.send(new CompleteMultipartUploadCommand({ Bucket: BUCKET, Key: key, UploadId: uploadId, MultipartUpload: { Parts: parts } }));
    return ok({ status: 'ok' });
  }

  // ── POST /media/multipart/abort ───────────────────────────────────────────────
  if (method === 'POST' && path === '/media/multipart/abort') {
    const { key, uploadId } = body;
    try { await s3.send(new AbortMultipartUploadCommand({ Bucket: BUCKET, Key: key, UploadId: uploadId })); } catch(e) {}
    return ok({ status: 'ok' });
  }

  // ── GET /media/speed-test-url ─────────────────────────────────────────────────
  if (method === 'GET' && path === '/media/speed-test-url') {
    const key = 'tmp/speedtest-' + Date.now() + '.bin';
    const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: BUCKET, Key: key, ContentType: 'application/octet-stream' }), { expiresIn: 120 });
    return ok({ uploadUrl });
  }

  // ── POST /connect/onboard ─────────────────────────────────────────────────────
  if (method === 'POST' && path === '/connect/onboard') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const RETURN_URL  = 'https://main.daiw44z798u76.amplifyapp.com/?connect=success';
    const REFRESH_URL = 'https://main.daiw44z798u76.amplifyapp.com/?connect=refresh';
    try {
      let accountId = creator.stripeAccountId;
      if (!accountId) {
        // Create a new Express connected account
        const acct = await stripeRequest('POST', '/v1/accounts', {
          type: 'express',
          country: 'US',
          email: creator.email || '',
          'capabilities[transfers][requested]': 'true',
          'metadata[username]': creator.username,
        });
        if (acct.error) return err(400, acct.error.message || 'Could not create Stripe account');
        accountId = acct.id;
        creator.stripeAccountId = accountId;
        await putCreator(creator);
      }
      // Verify account exists under this platform before creating link
      const acctCheck = await stripeRequest('GET', '/v1/accounts/' + accountId, null);
      if (acctCheck.error || acctCheck.id !== accountId) {
        // Account doesn't exist under this platform — clear it and create fresh
        creator.stripeAccountId = null;
        const newAcct = await stripeRequest('POST', '/v1/accounts', {
          type: 'express', country: 'US', email: creator.email || '',
          'capabilities[transfers][requested]': 'true',
          'metadata[username]': creator.username,
        });
        if (newAcct.error) return err(400, newAcct.error.message || 'Could not create Stripe account');
        accountId = newAcct.id;
        creator.stripeAccountId = accountId;
        await putCreator(creator);
      }
      const link = await stripeRequest('POST', '/v1/account_links', {
        account: accountId,
        refresh_url: REFRESH_URL,
        return_url: RETURN_URL,
        type: 'account_onboarding',
      });
      if (link.error) return err(400, link.error.message || 'Could not create onboarding link');
      return ok({ url: link.url });
    } catch(e) { return err(500, e.message || 'Stripe connection failed'); }
  }

  // ── POST /connect/disconnect ──────────────────────────────────────────────────
  if (method === 'POST' && path === '/connect/disconnect') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    delete creator.stripeAccountId;
    await putCreator(creator);
    return ok({ status: 'ok' });
  }

  // ── GET /connect/status ───────────────────────────────────────────────────────
  if (method === 'GET' && path === '/connect/status') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    if (!creator.stripeAccountId) return ok({ connected: false });
    try {
      const acct = await stripeRequest('GET', '/v1/accounts/' + creator.stripeAccountId, null);
      return ok({ connected: true, chargesEnabled: acct.charges_enabled, payoutsEnabled: acct.payouts_enabled, accountId: creator.stripeAccountId });
    } catch(e) { return ok({ connected: false }); }
  }

  // ── POST /payment/intent or /payment/stripe-intent ─────────────────────────
  if (method === 'POST' && (path === '/payment/intent' || path === '/payment/stripe-intent')) {
    const ip = event.requestContext?.identity?.sourceIp || event.requestContext?.http?.sourceIp || 'unknown';
    if (rateLimit('payment:' + ip, 20)) return err(429, 'Too many requests. Please slow down.');
    const { creatorUsername, dropId, amount, currency } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'CREATOR NOT FOUND');
    const params = {
      amount: Math.round(amount * 100),
      currency: (currency || 'usd').toLowerCase(),
      'payment_method_types[]': 'card',
      'metadata[dropId]': dropId,
      'metadata[creatorUsername]': creatorUsername,
      'metadata[purchaseId]': body.purchaseId || '',
      'description': 'PlayOnce drop access — @' + creatorUsername,
    };
    if (creator.stripeAccountId) {
      params['application_fee_amount'] = Math.round(amount * 100 * 0.20);
      params['transfer_data[destination]'] = creator.stripeAccountId;
    }
    const intent = await stripeRequest('POST', '/v1/payment_intents', params);
    if (intent.error) return err(400, intent.error.message || 'Payment error');
    return ok({ clientSecret: intent.client_secret, intentId: intent.id });
  }

// ── POST /payment/confirm or /payment/stripe-verify ────────────────────────
  if (method === 'POST' && (path === '/payment/confirm' || path === '/payment/stripe-verify')) {
    const { intentId, creatorUsername, dropId, amount, currency, purchaseId } = body;
    const intent = await stripeRequest('GET', '/v1/payment_intents/' + intentId, null);
    if (intent.status !== 'succeeded') return err(400, 'PAYMENT NOT CONFIRMED');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'CREATOR NOT FOUND');

    // Idempotency — check if webhook already recorded this payment
    const alreadyRecorded = (creator.sales || []).find(s => s.intentId === intentId);
    if (alreadyRecorded) {
      // Webhook got here first — just return ok, viewer already has access
      return ok({ status: 'ok', recorded: 'webhook' });
    }

    creator.grossRevenue = (creator.grossRevenue || 0) + (amount || 0);
    creator.paidViews    = (creator.paidViews    || 0) + 1;
    if (!Array.isArray(creator.sales)) creator.sales = [];
    creator.sales.push({ amount: parseFloat(amount || 0), dropId: String(dropId), earnedAt: Date.now(), intentId: intentId || null, purchaseId: purchaseId || null });
    const drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
    const cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(dropId));
    if (drop)  drop.views  = (drop.views  || 0) + 1;
    if (cdrop) cdrop.views = (cdrop.views || 0) + 1;
    await putCreator(creator);
    const dropTitle = drop?.title || cdrop?.title || dropId;
    notify(
      '💰 New payment — $' + (amount || 0) + ' ' + (currency || 'USD'),
      'Creator: @' + creatorUsername + '\nDrop: ' + dropTitle + '\nTotal views: ' + creator.paidViews,
      '💰'
    ).catch(() => {});
    return ok({ status: 'ok' });
  }

  // ── POST /payment/mpesa or /payment/mpesa-stk ──────────────────────────────
  if (method === 'POST' && (path === '/payment/mpesa' || path === '/payment/mpesa-stk')) {
    const { phone, amount, creatorUsername, dropId } = body;
    const CONSUMER_KEY    = process.env.MPESA_CONSUMER_KEY    || '';
    const CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET || '';
    const SHORTCODE       = process.env.MPESA_SHORTCODE       || '';
    const PASSKEY         = process.env.MPESA_PASSKEY         || '';
    const MPESA_ENV       = process.env.MPESA_ENV             || 'sandbox';
    const baseUrl         = MPESA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
    const https           = require('https');
    async function mpesaGet(path) {
      const auth = Buffer.from(CONSUMER_KEY + ':' + CONSUMER_SECRET).toString('base64');
      return new Promise((res, rej) => {
        const url = new URL(baseUrl + path);
        const req = https.request({ hostname: url.hostname, path: url.pathname + url.search, method: 'GET', headers: { 'Authorization': 'Basic ' + auth } }, r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>res(JSON.parse(d))); });
        req.on('error', rej); req.end();
      });
    }
    async function mpesaPost(path, payload) {
      const token = (await mpesaGet('/oauth/v1/generate?grant_type=client_credentials')).access_token;
      const body2 = JSON.stringify(payload);
      return new Promise((res, rej) => {
        const url = new URL(baseUrl + path);
        const req = https.request({ hostname: url.hostname, path: url.pathname, method: 'POST', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body2) } }, r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>res(JSON.parse(d))); });
        req.on('error', rej); req.write(body2); req.end();
      });
    }
    try {
      const ts = new Date().toISOString().replace(/[^0-9]/g,'').slice(0,14);
      const pwd = Buffer.from(SHORTCODE + PASSKEY + ts).toString('base64');
      const cleaned = phone.replace(/^0/, '254').replace(/[^0-9]/g,'');
      const res = await mpesaPost('/mpesa/stkpush/v1/processrequest', { BusinessShortCode: SHORTCODE, Password: pwd, Timestamp: ts, TransactionType: 'CustomerPayBillOnline', Amount: Math.ceil(amount), PartyA: cleaned, PartyB: SHORTCODE, PhoneNumber: cleaned, CallBackURL: 'https://ek96lj4uec.execute-api.eu-west-1.amazonaws.com/prod/payment/mpesa-callback', AccountReference: 'PlayOnce', TransactionDesc: 'Drop access' });
      return ok({ checkoutRequestId: res.CheckoutRequestID, responseCode: res.ResponseCode });
    } catch(e) { return err(500, 'M-Pesa error: ' + e.message); }
  }

  // ── GET /payment/mpesa-status or /payment/mpesa-poll ────────────────────────
  if (method === 'GET' && (path === '/payment/mpesa-status' || path === '/payment/mpesa-poll')) {
    const { checkoutRequestId, creatorUsername, dropId, amount } = qs;
    const CONSUMER_KEY    = process.env.MPESA_CONSUMER_KEY    || '';
    const CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET || '';
    const SHORTCODE       = process.env.MPESA_SHORTCODE       || '';
    const PASSKEY         = process.env.MPESA_PASSKEY         || '';
    const MPESA_ENV       = process.env.MPESA_ENV             || 'sandbox';
    const baseUrl         = MPESA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
    const https           = require('https');
    try {
      const auth = Buffer.from(CONSUMER_KEY + ':' + CONSUMER_SECRET).toString('base64');
      const tokenRes = await new Promise((res,rej)=>{ const url=new URL(baseUrl+'/oauth/v1/generate?grant_type=client_credentials'); const req=https.request({hostname:url.hostname,path:url.pathname+url.search,method:'GET',headers:{'Authorization':'Basic '+auth}},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res(JSON.parse(d)));});req.on('error',rej);req.end();});
      const token = tokenRes.access_token;
      const ts  = new Date().toISOString().replace(/[^0-9]/g,'').slice(0,14);
      const pwd = Buffer.from(SHORTCODE + PASSKEY + ts).toString('base64');
      const payload = JSON.stringify({ BusinessShortCode: SHORTCODE, Password: pwd, Timestamp: ts, CheckoutRequestID: checkoutRequestId });
      const queryRes = await new Promise((res,rej)=>{ const url=new URL(baseUrl+'/mpesa/stkpushquery/v1/query'); const req=https.request({hostname:url.hostname,path:url.pathname,method:'POST',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res(JSON.parse(d)));});req.on('error',rej);req.write(payload);req.end();});
      const rc = queryRes.ResultCode;
      if (rc === '0' || rc === 0) {
        const creator = await getCreator(creatorUsername);
        if (creator) {
          creator.grossRevenue = (creator.grossRevenue || 0) + parseFloat(amount || 0);
          creator.paidViews    = (creator.paidViews    || 0) + 1;
          await putCreator(creator);
        }
        return ok({ status: 'success' });
      }
      if (rc === '1037') return ok({ status: 'timeout' });
      if (rc === '1032') return ok({ status: 'cancelled' });
      return ok({ status: 'pending', rc });
    } catch(e) { return ok({ status: 'pending' }); }
  }

  // ── POST /refund/submit ───────────────────────────────────────────────────────
  // Per spec: platform is gatekeeper — we log request, auto-approve clear failures,
  // forward disputed cases to creator. No direct fan→creator interaction.
  if (method === 'POST' && path === '/refund/submit') {
    const { creatorUsername, dropId, purchaseId, reason, playStatus, playedPct,
            stallCount, stallTotalSec, title, price, currency, details } = body;
    if (!creatorUsername || !purchaseId) return err(400, 'Missing required fields');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');

    // Find the sale record to get the Stripe intentId for refunding
    const sale = (creator.sales || []).find(s => s.purchaseId === purchaseId);
    const intentId = sale?.intentId || null;

    // ── Routing: EVERYTHING goes to platform queue first, no exceptions ──────────
    // No auto-approval. You (the platform) see every request first.
    // From the admin panel you can: approve directly, deny, or forward to creator.
    const isCopyrightClaim = reason === 'Copyrighted or stolen content';
    let refundStatus = 'platform_review';
    let stripeRefundId = null;
    let routedTo = 'platform';

    // Build refund record
    const refundRecord = {
      id: Date.now(),
      purchaseId, dropId, title: title || dropId,
      price: price || 0, currency: currency || 'USD',
      reason, playStatus, playedPct: playedPct || 0,
      stallCount: stallCount || 0, stallTotalSec: stallTotalSec || 0,
      intentId, stripeRefundId,
      refundStatus, routedTo,
      submittedAt: Date.now(),
      creatorUsername,
      // 48h deadline for creator to respond (only for creator-routed disputes)
      creatorDeadline: routedTo === 'creator' ? Date.now() + CREATOR_DEADLINE_MS : null,
    };

    if (!Array.isArray(creator.refundRequests)) creator.refundRequests = [];
    creator.refundRequests.push(refundRecord);
    await putCreator(creator);

    // Notify platform — every refund gets an alert, urgency varies by type
    const notifyLines = [
      `Creator: @${creatorUsername}`,
      `Drop: ${title || dropId}`,
      `Amount: $${price || 0} ${currency || 'USD'}`,
      `Reason: ${reason}`,
      `Play status: ${playStatus || 'unknown'}${playedPct ? ' (' + playedPct + '%)' : ''}`,
      `Route: ${routedTo}`,
      details ? `Details: ${details}` : null,
    ].filter(Boolean).join('\n');

    if (isCopyrightClaim) {
      notify('🚨 Copyright claim — action required', notifyLines, '🚨').catch(() => {});
    } else {
      notify('💸 New refund request — review needed', notifyLines, '💸').catch(() => {});
    }

    return ok({ status: 'ok', autoApproved: refundStatus === 'approved', refundStatus, routedTo });
  }

  // ── POST /refund/action — creator approves or denies a disputed refund ────────
  if (method === 'POST' && path === '/refund/action') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { refundId, action, response } = body;
    if (!Array.isArray(creator.refundRequests)) return ok({ status: 'ok' });
    const req2 = creator.refundRequests.find(r => String(r.id) === String(refundId));
    if (!req2) return err(404, 'Request not found');

    if (action === 'approve') {
      // Issue actual Stripe refund
      if (req2.intentId) {
        try {
          const refundParams = new URLSearchParams();
          refundParams.append('payment_intent', req2.intentId);
          refundParams.append('reason', 'requested_by_customer');
          const refundResult = await stripeRequestRaw('POST', '/v1/refunds', refundParams.toString());
          if (refundResult.id) req2.stripeRefundId = refundResult.id;
        } catch(e) { console.error('Refund on approve failed:', e.message); }
      }
      // Remove from creator earnings
      creator.sales = (creator.sales || []).filter(s => s.purchaseId !== req2.purchaseId);
      creator.grossRevenue = Math.max(0, (creator.grossRevenue || 0) - (req2.price || 0));
      req2.refundStatus = 'approved';
      req2.creatorResponse = response || 'Refund approved.';
    } else {
      req2.refundStatus = 'denied';
      req2.creatorResponse = response || 'Refund request denied.';
    }
    req2.resolvedAt = Date.now();
    await putCreator(creator);
    // Notify platform of creator's decision
    const actionEmoji = action === 'approve' ? '✅' : '❌';
    notify(
      actionEmoji + ' Creator ' + (action === 'approve' ? 'approved' : 'denied') + ' refund — @' + creator.username,
      'Drop: ' + (req2.title || req2.dropId) + '\nAmount: $' + (req2.price || 0) + '\nReason: ' + (req2.reason || 'N/A') + (response ? '\nCreator note: ' + response : ''),
      actionEmoji
    ).catch(() => {});
    return ok({ status: 'ok', refundStatus: req2.refundStatus });
  }

  // ── GET /refund/status — viewer polls for refund decision ─────────────────────
  if (method === 'GET' && path === '/refund/status') {
    const { creatorUsername, purchaseId } = qs;
    if (!creatorUsername || !purchaseId) return err(400, 'Missing params');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Not found');
    const req2 = (creator.refundRequests || []).find(r => r.purchaseId === purchaseId);
    if (!req2) return ok({ refundStatus: 'not_found' });
    return ok({ refundStatus: req2.refundStatus, creatorResponse: req2.creatorResponse || null });
  }

  // ── Verification endpoints ───────────────────────────────────────────────────
  if (path.startsWith('/verify/')) {
    const creator = await getAuth();
    if (path === '/verify/send-code' || path === '/verify/send-otp') {
      const target = creator || (body.username ? await getCreator(body.username) : null);
      if (!target) return err(401, 'UNAUTHORIZED');
      const verifyEmail = body.email || target.email;
      if (!verifyEmail) return err(400, 'EMAIL REQUIRED');
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      target._otp = code; target._otpAt = Date.now(); target._otpEmail = verifyEmail;
      await putCreator(target);
      try { await sendEmail(verifyEmail, 'Your PlayOnce verification code', 'Your verification code is: ' + code + '\n\nEnter this in the app to verify your account.\nExpires in 10 minutes.\n\nPlayOnce'); } catch(e) { console.error('Send email failed:', e.message); }
      const isDev = !process.env.SES_FROM_EMAIL;
      return ok({ status: 'ok', ...(isDev ? { _devCode: code } : {}) });
    }
    if (path === '/verify/confirm-code' || path === '/verify/confirm-otp') {
      const target = creator || (body.username ? await getCreator(body.username) : null);
      if (!target) return err(401, 'UNAUTHORIZED');
      const { code } = body;
      const verifyEmail = target._otpEmail || body.email || target.email || '';
      if (!target._otp || target._otp !== code) return err(400, 'INVALID CODE');
      if (Date.now() - (target._otpAt || 0) > 10 * 60 * 1000) return err(400, 'CODE EXPIRED');
      const isBrand = !isFreeEmailDomain(verifyEmail);
      if (isBrand) {
        target.verified = true; target.verifiedBadge = 'brand'; target.verifiedType = 'brand'; target.verifiedDomain = verifyEmail.split('@')[1];
        delete target._otp; delete target._otpAt; delete target._otpEmail;
        await putCreator(target);
        return ok({ status: 'verified', verifiedBadge: 'brand' });
      }
      delete target._otp; delete target._otpAt; delete target._otpEmail;
      await putCreator(target);
      return ok({ status: 'needs_subscription' });
    }
    if (path === '/verify/domain-free') {
      const { email } = body;
      return ok({ isFree: isFreeEmailDomain(email) });
    }
    if (path === '/verify/create-subscription' || path === '/verify/subscribe') {
      const creator2 = creator || (body.username ? await getCreator(body.username) : null);
      if (!creator2) return err(401, 'UNAUTHORIZED');
      const PRICE_ID = process.env.STRIPE_VERIFY_PRICE_ID;
      if (!PRICE_ID) return err(500, 'Verification price not configured');
      const { paymentMethodId } = body;
      if (!paymentMethodId) return err(400, 'PAYMENT METHOD REQUIRED');

      // Create or reuse Stripe customer — verify it exists first
      let customerId = creator2.stripeCustomerId;
      if (customerId) {
        // Verify customer exists under current Stripe account
        const check = await stripeRequest('GET', '/v1/customers/' + customerId, null);
        if (check.error || check.deleted) {
          // Stale customer from old Stripe account — clear and recreate
          customerId = null;
          delete creator2.stripeCustomerId;
        }
      }
      if (!customerId) {
        const customer = await stripeRequest('POST', '/v1/customers', {
          email: creator2.email || '',
          'metadata[username]': creator2.username
        });
        if (customer.error) return err(400, customer.error.message || 'Could not create customer');
        customerId = customer.id;
        creator2.stripeCustomerId = customerId;
        await putCreator(creator2);
      }

      // Attach payment method to customer
      await stripeRequest('POST', `/v1/payment_methods/${paymentMethodId}/attach`, { customer: customerId });

      // Set as default payment method
      await stripeRequest('POST', `/v1/customers/${customerId}`, { 'invoice_settings[default_payment_method]': paymentMethodId });

      // Create subscription — use explicit array notation for form encoding
      const subParams = new URLSearchParams();
      subParams.append('customer', customerId);
      subParams.append('items[0][price]', PRICE_ID);
      subParams.append('payment_settings[payment_method_types][0]', 'card');
      subParams.append('payment_settings[save_default_payment_method]', 'on_subscription');
      subParams.append('expand[0]', 'latest_invoice.payment_intent');

      const sub = await stripeRequestRaw('POST', '/v1/subscriptions', subParams.toString());

      if (sub.error) return err(400, sub.error.message || 'Subscription failed');

      const invoice = sub.latest_invoice;
      const intent = invoice?.payment_intent;

      // If payment requires action (3D Secure) return client secret
      if (intent && intent.status === 'requires_action') {
        return ok({ status: 'requires_action', clientSecret: intent.client_secret });
      }

      // Payment succeeded — mark verified
      if (sub.status === 'active' || sub.status === 'trialing' || intent?.status === 'succeeded') {
        creator2.verified = true; creator2.verifiedBadge = 'paid'; creator2.verifiedType = 'paid';
        creator2.stripeSubId = sub.id;
        await putCreator(creator2);
        return ok({ status: 'verified', verifiedBadge: 'paid' });
      }

      return err(400, 'Payment not completed. Status: ' + (intent?.status || sub.status));
    }
    if (path === '/verify/subscription-complete') {
      // Legacy Checkout Session callback — kept for backwards compat
      const { sessionId, username } = body;
      const session = await stripeRequest('GET', '/v1/checkout/sessions/' + sessionId, null);
      if (session.payment_status !== 'paid') return err(400, 'NOT PAID');
      const target = await getCreator(username);
      if (!target) return err(404, 'NOT FOUND');
      target.verified = true; target.verifiedBadge = 'paid'; target.verifiedType = 'paid'; target.stripeSubId = session.subscription;
      await putCreator(target);
      return ok({ status: 'verified', verifiedBadge: 'paid' });
    }
    if (path === '/verify/cancel-subscription' || path === '/verify/cancel') {
      const target = creator;
      if (!target) return err(401, 'UNAUTHORIZED');
      if (target.stripeSubId) { try { await stripeRequest('DELETE', '/v1/subscriptions/' + target.stripeSubId, null); } catch(e) {} }
      target.verified = false; delete target.verifiedBadge; delete target.stripeSubId;
      await putCreator(target);
      return ok({ status: 'ok' });
    }
  }

  // ── POST /payment/record-sale ─────────────────────────────────────────────────
  if (method === 'POST' && path === '/payment/record-sale') {
    const { creatorUsername, dropId, amount } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'CREATOR NOT FOUND');
    creator.grossRevenue = (creator.grossRevenue || 0) + parseFloat(amount || 0);
    creator.paidViews    = (creator.paidViews    || 0) + 1;
    // Record individual sale with timestamp for 3-day hold logic
    if (!Array.isArray(creator.sales)) creator.sales = [];
    creator.sales.push({ amount: parseFloat(amount || 0), dropId: String(dropId), earnedAt: Date.now() });
    const drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
    const cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(dropId));
    if (drop)  drop.views  = (drop.views  || 0) + 1;
    if (cdrop) cdrop.views = (cdrop.views || 0) + 1;
    await putCreator(creator);
    return ok({ status: 'ok', grossRevenue: creator.grossRevenue, paidViews: creator.paidViews });
  }

  // ── POST /payment/withdraw ────────────────────────────────────────────────────
  if (method === 'POST' && path === '/payment/withdraw') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    if (!creator.stripeAccountId) return err(400, 'No payout account connected');
    const HOLD_MS = 3 * 24 * 60 * 60 * 1000;
    const now = Date.now();
    const unlocked = (creator.sales || []).filter(s => (s.earnedAt || 0) + HOLD_MS <= now);
    const available = +unlocked.reduce((sum, s) => sum + s.amount * 0.80, 0).toFixed(2);
    // Also include legacy grossRevenue if no sales array
    const legacyAvailable = (!creator.sales || creator.sales.length === 0)
      ? +((creator.grossRevenue || 0) * 0.80).toFixed(2) : 0;
    const totalAvailable = +(available + legacyAvailable).toFixed(2);
    if (totalAvailable <= 0) return err(400, 'No funds available yet — funds unlock on day 4');
    // Transfer from platform balance to creator connected account
    const amountCents = Math.round(totalAvailable * 100);
    const transfer = await stripeRequest('POST', '/v1/transfers', {
      amount: amountCents, currency: 'usd',
      destination: creator.stripeAccountId,
      description: 'PlayOnce creator payout'
    });
    if (transfer.error) return err(400, transfer.error.message || 'Transfer failed');
    // Remove unlocked sales, keep locked ones
    creator.sales = (creator.sales || []).filter(s => (s.earnedAt || 0) + HOLD_MS > now);
    creator.grossRevenue = 0;
    await putCreator(creator);
    return ok({ status: 'ok', transferred: totalAvailable });
  }

  // ── POST /cron/autopayout — auto-pay all creators with unlocked funds ─────────
  // Called daily by EventBridge — processes all creators automatically
  if (method === 'POST' && path === '/cron/autopayout') {
    const secret = process.env.CRON_SECRET || process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-cron-key'] || body.key || '';
    if (!secret || provided !== secret) return err(403, 'FORBIDDEN');

    const HOLD_MS = 3 * 24 * 60 * 60 * 1000;
    const now = Date.now();
    const index = await getUserIndex();
    const results = { paid: [], skipped: [], errors: [] };

    for (const u of (index || [])) {
      try {
        const creator = await getCreator(u.username);
        if (!creator || creator.banned || creator.payoutsFrozen) continue;
        if (!creator.stripeAccountId) continue;

        // Calculate unlocked funds
        const unlocked = (creator.sales || []).filter(s => (s.earnedAt || 0) + HOLD_MS <= now);
        const legacyAvailable = (!creator.sales || creator.sales.length === 0)
          ? +((creator.grossRevenue || 0) * 0.80).toFixed(2) : 0;
        const available = +unlocked.reduce((sum, s) => sum + s.amount * 0.80, 0).toFixed(2);
        const totalAvailable = +(available + legacyAvailable).toFixed(2);

        if (totalAvailable < 0.50) { results.skipped.push(u.username + ' ($' + totalAvailable + ')'); continue; } // skip tiny amounts

        // Transfer to creator
        const amountCents = Math.round(totalAvailable * 100);
        const transfer = await stripeRequest('POST', '/v1/transfers', {
          amount: amountCents, currency: 'usd',
          destination: creator.stripeAccountId,
          description: 'PlayOnce auto-payout — @' + creator.username,
          'metadata[username]': creator.username,
          'metadata[type]': 'autopayout',
        });

        if (transfer.error) {
          results.errors.push(u.username + ': ' + (transfer.error.message || 'Transfer failed'));
          continue;
        }

        // Clear paid sales, keep locked ones
        creator.sales = (creator.sales || []).filter(s => (s.earnedAt || 0) + HOLD_MS > now);
        creator.grossRevenue = 0;
        await putCreator(creator);

        // Email creator
        if (creator.email) {
          try {
            await sendEmail(creator.email, 'Your PlayOnce payout — $' + totalAvailable,
              'Hi @' + creator.username + ',\n\n$' + totalAvailable + ' has been transferred to your Stripe account.\n\nIt will appear in your bank account within 2-3 business days depending on your Stripe payout schedule.\n\nPlayOnce Support\nsupport@playonce.app'
            );
          } catch(e) {}
        }

        results.paid.push('@' + u.username + ' $' + totalAvailable);
        notify('💸 Auto-payout sent — $' + totalAvailable + ' to @' + creator.username, 'Transfer successful', '💸').catch(() => {});

      } catch(e) {
        results.errors.push(u.username + ': ' + e.message);
      }
    }

    console.log('Auto-payout results:', JSON.stringify(results));
    return ok({ status: 'ok', paid: results.paid.length, skipped: results.skipped.length, errors: results.errors.length, details: results });
  }

  // ── GET /admin/ping — verify admin key works ────────────────────────────────
  if (method === 'GET' && path === '/admin/ping') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret) return err(500, 'ADMIN_SECRET not set in Lambda environment variables');
    if (provided !== adminSecret) return err(403, 'Wrong key — check ADMIN_SECRET in Lambda');
    return ok({ status: 'ok', message: 'Admin key valid', timestamp: Date.now() });
  }

  // ── GET /admin/refund-queue — platform sees all pending refunds ──────────────
  if (method === 'GET' && path === '/admin/refund-queue') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const allRefunds = [];
    try {
      // Use user index for fast lookup instead of scanning all S3 objects
      const index = await getUserIndex();
      const usernames = (index || []).map(u => u.username).filter(Boolean);
      // Fetch all in parallel (batches of 10)
      for (let i = 0; i < usernames.length; i += 10) {
        const batch = usernames.slice(i, i + 10);
        const results = await Promise.allSettled(batch.map(u => getCreator(u)));
        results.forEach(r => {
          if (r.status === 'fulfilled' && r.value && r.value.refundRequests) {
            r.value.refundRequests.forEach(req => {
              if (req.refundStatus === 'pending' || req.refundStatus === 'platform_review') {
                allRefunds.push({ ...req, _creatorUsername: r.value.username });
              }
            });
          }
        });
      }
    } catch(e) { return err(500, e.message); }
    allRefunds.sort((a,b) => b.submittedAt - a.submittedAt);
    return ok({ total: allRefunds.length, refunds: allRefunds });
  }

  // ── POST /cron/copyright-review — auto-restore drops where proof deadline passed ─
  if (method === 'POST' && path === '/cron/copyright-review') {
    const secret = process.env.CRON_SECRET || process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-cron-key'] || event.headers?.['x-admin-key'] || body.key || body.adminKey || '';
    if (!secret || provided !== secret) return err(403, 'FORBIDDEN');

    const now = Date.now();
    const index = await getUserIndex();
    const results = { restored: [], skipped: [], errors: [] };
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@playonce.app';

    for (const u of (index || [])) {
      try {
        const creator = await getCreator(u.username);
        if (!creator) continue;
        const SIX_HOURS_MS = 6 * 60 * 60 * 1000;
        const claims = (creator.refundRequests || []).filter(r => {
          if (!r.isCopyrightClaim) return false;
          if (r.refundStatus !== 'platform_review') return false;
          if (r.proofConfirmed) return false;
          // Has deadline set — check if passed
          if (r.proofDeadline) return now > r.proofDeadline;
          // No deadline set (old claim) — restore if older than 6 hours
          return r.submittedAt && (now - r.submittedAt) > SIX_HOURS_MS;
        });
        if (!claims.length) continue;

        let changed = false;
        for (const claim of claims) {
          // Find drop by ID first, then fall back to title match (old claims stored title as dropId)
          let drop  = (creator.drops        || []).find(d => String(d.id) === String(claim.dropId));
          let cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(claim.dropId));
          if (!drop && !cdrop) {
            const t = (claim.title || '').toLowerCase();
            drop  = (creator.drops        || []).find(d => (d.title||'').toLowerCase() === t);
            cdrop = (creator.creatorDrops || []).find(d => (d.title||'').toLowerCase() === t);
          }

          // Check drop not expired before restoring
          const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
          const start = drop?.scheduledAt || drop?.uploadedAt || cdrop?.scheduledAt || cdrop?.uploadedAt || 0;
          const isExpired = start && (now - start) > THREE_DAYS_MS;

          if (!isExpired && (drop || cdrop)) {
            // Restore drop
            if (drop)  { drop.live  = true; delete drop.copyrightHold;  delete drop.copyrightReason;  delete drop.copyrightFlaggedAt; }
            if (cdrop) { cdrop.live = true; delete cdrop.copyrightHold; delete cdrop.copyrightReason; delete cdrop.copyrightFlaggedAt; }
            results.restored.push('@' + u.username + ' — ' + (claim.title || claim.dropId));
          } else {
            results.skipped.push('@' + u.username + ' — expired or not found');
          }

          // Mark claim as auto-resolved
          claim.refundStatus = 'auto_restored';
          claim.resolvedAt = now;
          claim.resolvedBy = 'auto_no_proof';
          changed = true;

          // Email claimant — proof window expired
          if (claim.claimantEmail) {
            sendEmail(claim.claimantEmail,
              'Copyright claim closed — no proof received — PlayOnce',
              'Your copyright claim for "' + (claim.title || 'Unknown') + '" has been closed.\n\nReason: No proof of ownership was received within the 6-hour window.\n\nThe drop has been restored to the creator vault.\n\nIf you believe this is an error, contact ' + supportEmail + ' with your proof.\n\nPlayOnce Support\n' + supportEmail
            ).catch(() => {});
          }

          // Email creator — drop restored
          if (creator.email && !isExpired) {
            sendEmail(creator.email,
              'Your drop has been restored — PlayOnce',
              'Hi @' + creator.username + ',\n\nYour drop "' + (claim.title || 'Unknown') + '" has been automatically restored.\n\nThe copyright claimant did not provide proof of ownership within 6 hours, so the claim was dismissed.\n\nPlayOnce Support\n' + supportEmail
            ).catch(() => {});
          }

          notify('✅ Auto-restored — no proof — @' + u.username, 'Drop: ' + (claim.title || claim.dropId), '✅').catch(() => {});
        }

        if (changed) await putCreator(creator);
      } catch(e) {
        results.errors.push(u.username + ': ' + e.message);
      }
    }

    console.log('Copyright review results:', JSON.stringify(results));
    return ok({ status: 'ok', restored: results.restored.length, skipped: results.skipped.length, errors: results.errors.length, details: results });
  }

  // ── POST /admin/confirm-proof — mark claim proof verified, keep drop hidden ────
  if (method === 'POST' && path === '/admin/confirm-proof') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, claimId } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    const claim = (creator.refundRequests || []).find(r => String(r.id) === String(claimId));
    if (!claim) return err(404, 'Claim not found');
    claim.proofConfirmed = true;
    claim.proofConfirmedAt = Date.now();
    // Remove auto-restore deadline — proof verified, keep hidden until manual restore
    delete claim.proofDeadline;
    await putCreator(creator);
    // Email claimant — proof confirmed
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@playonce.app';
    if (claim.claimantEmail) {
      sendEmail(claim.claimantEmail,
        'Your copyright claim has been verified — PlayOnce',
        'Your proof of ownership for "' + (claim.title || 'Unknown') + '" has been reviewed and confirmed.\n\nThe drop will remain hidden while the matter is resolved.\n\nThank you for protecting your content.\n\nPlayOnce Support\n' + supportEmail
      ).catch(() => {});
    }
    return ok({ status: 'ok', confirmed: claimId });
  }

  // ── POST /admin/dismiss-claim — remove copyright claim from queue ─────────────
  if (method === 'POST' && path === '/admin/dismiss-claim') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, claimId } = body;
    if (!creatorUsername || !claimId) return err(400, 'creatorUsername and claimId required');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    // Remove the claim from refundRequests
    const before = (creator.refundRequests || []).length;
    creator.refundRequests = (creator.refundRequests || []).filter(r => String(r.id) !== String(claimId));
    if (creator.refundRequests.length === before) return err(404, 'Claim not found');
    await putCreator(creator);
    return ok({ status: 'ok', dismissed: claimId });
  }

  // ── POST /admin/refund-action — platform approves or denies any refund ────────
  if (method === 'POST' && path === '/admin/refund-action') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, refundId, action: refundAction } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    const req2 = (creator.refundRequests || []).find(r => String(r.id) === String(refundId));
    if (!req2) return err(404, 'Refund request not found');
    if (refundAction === 'approve') {
      if (req2.intentId) {
        try {
          const p = new URLSearchParams();
          p.append('payment_intent', req2.intentId);
          p.append('reason', 'requested_by_customer');
          const r = await stripeRequestRaw('POST', '/v1/refunds', p.toString());
          if (r.id) req2.stripeRefundId = r.id;
        } catch(e) { console.error('Platform refund failed:', e.message); }
      }
      creator.sales = (creator.sales || []).filter(s => s.purchaseId !== req2.purchaseId);
      creator.grossRevenue = Math.max(0, (creator.grossRevenue || 0) - (req2.price || 0));
      req2.refundStatus = 'approved'; req2.resolvedAt = Date.now(); req2.resolvedBy = 'platform';
    } else {
      req2.refundStatus = 'denied'; req2.resolvedAt = Date.now(); req2.resolvedBy = 'platform';
    }
    await putCreator(creator);
    notify(
      `Refund ${req2.refundStatus} by platform`,
      `Creator: @${creatorUsername}\nDrop: ${req2.title || req2.dropId}\nAmount: $${req2.price || 0}`,
      req2.refundStatus === 'approved' ? '✅' : '❌'
    ).catch(() => {});
    return ok({ status: 'ok', refundStatus: req2.refundStatus });
  }

  // ── POST /admin/check-deadlines — auto-approve expired creator refunds ────────
  if (method === 'POST' && path === '/admin/check-deadlines') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const now = Date.now(); let processed = 0;
    try {
      const index = await getUserIndex();
      const usernames = (index || []).map(u => u.username).filter(Boolean);
      for (let i = 0; i < usernames.length; i += 10) {
        const batch = usernames.slice(i, i + 10);
        const results = await Promise.allSettled(batch.map(u => getCreator(u)));
        for (const res of results) {
          if (res.status !== 'fulfilled' || !res.value) continue;
          const c = res.value; let changed = false;
          for (const req of (c.refundRequests || [])) {
            if (req.refundStatus === 'pending' && req.creatorDeadline && now > req.creatorDeadline) {
              if (req.intentId) {
                try {
                  const p = new URLSearchParams();
                  p.append('payment_intent', req.intentId);
                  p.append('reason', 'requested_by_customer');
                  const refundResult = await stripeRequestRaw('POST', '/v1/refunds', p.toString());
                  if (refundResult.id) req.stripeRefundId = refundResult.id;
                } catch(e) {}
              }
              req.refundStatus = 'approved'; req.resolvedAt = now; req.resolvedBy = 'platform_auto_deadline';
              c.sales = (c.sales || []).filter(s => s.purchaseId !== req.purchaseId);
              c.grossRevenue = Math.max(0, (c.grossRevenue || 0) - (req.price || 0));
              changed = true; processed++;
            }
          }
          if (changed) await putCreator(c);
        }
      }
    } catch(e) { return err(500, e.message); }
    return ok({ status: 'ok', processed });
  }

  // ── POST /admin/flag-copyright — hide drop, email creator ──────────────────
  if (method === 'POST' && path === '/admin/flag-copyright') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, dropId, reason } = body;
    if (!creatorUsername || !dropId) return err(400, 'creatorUsername and dropId required');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');

    // Find drop by ID first, then fall back to title match
    let drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
    let cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(dropId));
    // Fallback: search by title (dropId may be a title string from refund queue)
    if (!drop && !cdrop) {
      drop  = (creator.drops        || []).find(d => (d.title||'').toLowerCase() === String(dropId).toLowerCase());
      cdrop = (creator.creatorDrops || []).find(d => (d.title||'').toLowerCase() === String(dropId).toLowerCase());
    }
    if (!drop && !cdrop) return err(404, 'Drop not found — check creator username and drop ID');

    const flagReason = reason || 'Potential copyright violation';
    const flaggedAt  = Date.now();
    if (drop)  { drop.live  = false; drop.copyrightHold  = true; drop.copyrightReason  = flagReason; drop.copyrightFlaggedAt  = flaggedAt; }
    if (cdrop) { cdrop.live = false; cdrop.copyrightHold = true; cdrop.copyrightReason = flagReason; cdrop.copyrightFlaggedAt = flaggedAt; }
    await putCreator(creator);

    // Email the creator — only if not already flagged (viewer claim already sent one)
    const dropTitle = drop?.title || cdrop?.title || dropId;
    const alreadyFlagged = (drop?.copyrightFlaggedAt || cdrop?.copyrightFlaggedAt);
    const supportEmail = process.env.SUPPORT_EMAIL || process.env.SES_FROM_EMAIL || 'support@playonce.app';
    if (creator.email && !alreadyFlagged) {
      try {
        await sendEmail(
          creator.email,
          'Your drop has been temporarily hidden — PlayOnce',
          `Hi @${creator.username},

Your drop "${dropTitle}" has been temporarily hidden from your vault due to a copyright claim.

Reason: ${flagReason}

If you own this content and believe this is a mistake, please reply to this email with proof of ownership (e.g. original file, creation date, license).

Once we review your proof, your drop will be restored within 6 hours.

If you do not respond within 7 days, the drop will be permanently removed.

PlayOnce Support
${supportEmail}`
        );
      } catch(e) { console.error('Copyright email failed:', e.message); }
    }

    return ok({ status: 'ok', dropTitle, creatorEmail: creator.email || null });
  }

  // ── POST /admin/restore-drop — clear copyright hold, make live again ─────────
  if (method === 'POST' && path === '/admin/restore-drop') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, dropId } = body;
    if (!creatorUsername || !dropId) return err(400, 'creatorUsername and dropId required');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');

    const drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
    const cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(dropId));
    if (!drop && !cdrop) return err(404, 'Drop not found');

    const THREE_DAYS_MS_R = 3 * 24 * 60 * 60 * 1000;
    const now_r = Date.now();
    // Only restore live if not expired
    if (drop)  {
      const start_r = (drop.scheduledAt && drop.scheduledAt > (drop.uploadedAt||0)) ? drop.scheduledAt : (drop.uploadedAt||0);
      const expired_r = start_r > 0 && (now_r - start_r) >= THREE_DAYS_MS_R;
      drop.live  = !expired_r;
      delete drop.copyrightHold; delete drop.copyrightReason; delete drop.copyrightFlaggedAt;
    }
    if (cdrop) {
      const start_r2 = (cdrop.scheduledAt && cdrop.scheduledAt > (cdrop.uploadedAt||0)) ? cdrop.scheduledAt : (cdrop.uploadedAt||0);
      const expired_r2 = start_r2 > 0 && (now_r - start_r2) >= THREE_DAYS_MS_R;
      cdrop.live = !expired_r2;
      delete cdrop.copyrightHold; delete cdrop.copyrightReason; delete cdrop.copyrightFlaggedAt;
    }
    await putCreator(creator);

    // Email creator that their drop is restored
    const dropTitle = drop?.title || cdrop?.title || dropId;
    if (creator.email) {
      try {
        await sendEmail(
          creator.email,
          'Your drop has been restored — PlayOnce',
          `Hi @${creator.username},

Good news! Your drop "${dropTitle}" has been reviewed and restored to your vault. It is now live and visible to viewers.

Thank you for your patience.

PlayOnce Support`
        );
      } catch(e) {}
    }

    return ok({ status: 'ok', dropTitle });
  }

  // ── GET /admin/creator-drops — list all drops for a creator (for admin panel) ─
  if (method === 'GET' && path === '/admin/creator-drops') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { username } = qs;
    if (!username) return err(400, 'username required');
    const creator = await getCreator(username);
    if (!creator) return err(404, 'Creator not found');
    const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
    const nowTs = Date.now();
    const drops = (creator.creatorDrops || []).map(d => {
      const start = (d.scheduledAt && d.scheduledAt > (d.uploadedAt||0)) ? d.scheduledAt : (d.uploadedAt||0);
      const expired = start ? (nowTs - start) > THREE_DAYS_MS : false;
      return {
        id: d.id, title: d.title, price: d.price, live: d.live,
        views: d.views || 0, uploadedAt: d.uploadedAt,
        scheduledAt: d.scheduledAt || null,
        expired,
        copyrightHold: d.copyrightHold || false,
        copyrightReason: d.copyrightReason || null,
      };
    });
    return ok({ username: creator.username, email: creator.email, drops });
  }

  // ── POST /admin/strike — add a strike to a creator ────────────────────────────
  if (method === 'POST' && path === '/admin/strike') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, reason, action: strikeAction } = body;
    if (!creatorUsername) return err(400, 'creatorUsername required');
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    if (!Array.isArray(creator.strikes)) creator.strikes = [];
    const strike = { id: Date.now(), reason: reason || 'Violation', action: strikeAction || 'warning', issuedAt: Date.now() };
    creator.strikes.push(strike);
    const strikeCount = creator.strikes.length;
    // Auto-escalate based on count
    if (strikeAction === 'freeze' || strikeCount === 2) {
      creator.payoutsFrozen = true;
      creator.payoutsFrozenAt = Date.now();
      creator.payoutsFrozenReason = reason || 'Second strike';
    }
    if (strikeAction === 'ban' || strikeCount >= 3) {
      creator.banned = true;
      creator.bannedAt = Date.now();
      creator.bannedReason = reason || 'Third strike — auto-ban';
      // Hide all drops
      (creator.drops || []).forEach(d => { d.live = false; });
      (creator.creatorDrops || []).forEach(d => { d.live = false; });
    }
    await putCreator(creator);
    // Email creator
    if (creator.email) {
      const msgs = {
        warning: `You have received a warning on your PlayOnce account.\n\nReason: ${reason}\n\nThis is strike ${strikeCount} of 3. A third strike will result in a permanent ban.`,
        freeze: `Your PlayOnce payouts have been frozen.\n\nReason: ${reason}\n\nYour earnings will be held for 30 days pending review. Contact ${process.env.SUPPORT_EMAIL || process.env.ADMIN_EMAIL || 'support@playonce.app'} to appeal.`,
        ban: `Your PlayOnce account has been permanently banned.\n\nReason: ${reason}\n\nAll your drops have been removed. If you believe this is a mistake, contact ${process.env.SUPPORT_EMAIL || process.env.ADMIN_EMAIL || 'support@playonce.app'} within 14 days.`
      };
      const subject = { warning: 'Account warning — PlayOnce', freeze: 'Payouts frozen — PlayOnce', ban: 'Account banned — PlayOnce' };
      try { await sendEmail(creator.email, subject[strikeAction] || 'Account notice — PlayOnce', msgs[strikeAction] || msgs.warning); } catch(e) {}
    }
    // Notify platform
    const strikeEmoji = strikeAction === 'ban' ? '🚫' : strikeAction === 'freeze' ? '🔒' : '⚠️';
    notify(
      `Creator ${strikeAction}: @${creatorUsername}`,
      `Strike ${strikeCount}/3\nReason: ${reason}\nStatus: ${creator.banned ? 'BANNED' : creator.payoutsFrozen ? 'FROZEN' : 'WARNING ISSUED'}`,
      strikeEmoji
    ).catch(() => {});

    return ok({ status: 'ok', strikeCount, banned: creator.banned || false, frozen: creator.payoutsFrozen || false });
  }

  // ── POST /admin/unban ─────────────────────────────────────────────────────────
  if (method === 'POST' && path === '/admin/unban') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    creator.banned = false; creator.payoutsFrozen = false;
    creator.strikes = []; // Clear all strikes on unban
    delete creator.bannedAt; delete creator.bannedReason;
    delete creator.payoutsFrozenAt; delete creator.payoutsFrozenReason;
    // Restore drops that were hidden by the ban
    (creator.drops || []).forEach(d => { if (!d.copyrightHold) d.live = true; });
    (creator.creatorDrops || []).forEach(d => { if (!d.copyrightHold) d.live = true; });
    await putCreator(creator);
    const supportEmail = process.env.SUPPORT_EMAIL || process.env.ADMIN_EMAIL || 'support@playonce.app';
    if (creator.email) {
      try {
        await sendEmail(creator.email, 'Account reinstated — PlayOnce',
          'Hi @' + creator.username + ',\n\nYour PlayOnce account has been fully reinstated. All strikes have been cleared and your drops are live again.\n\nYou can now publish new drops and receive payouts.\n\nPlayOnce Support\n' + supportEmail
        );
      } catch(e) { console.warn('Unban email failed:', e.message); }
    }
    notify('↩ @' + creator.username + ' unbanned — strikes cleared', 'Account fully reinstated', '↩').catch(() => {});
    return ok({ status: 'ok' });
  }

  // ── GET /admin/creators — list all creators with strike/ban status ─────────────
  if (method === 'GET' && path === '/admin/creators') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    try {
      const index = await getUserIndex();
      const usernames = (index || []).map(u => u.username).filter(Boolean);
      const creators = [];
      for (let i = 0; i < usernames.length; i += 10) {
        const batch = usernames.slice(i, i + 10);
        const results = await Promise.allSettled(batch.map(u => getCreator(u)));
        results.forEach(r => {
          if (r.status === 'fulfilled' && r.value) {
            const c = r.value;
            creators.push({
              username: c.username, email: c.email || '',
              createdAt: c.createdAt || 0,
              grossRevenue: c.grossRevenue || 0,
              paidViews: c.paidViews || 0,
              dropCount: (c.creatorDrops || []).length,
              banned: c.banned || false,
              payoutsFrozen: c.payoutsFrozen || false,
              strikes: (c.strikes || []),
              strikeCount: (c.strikes || []).length,
              refundCount: (c.refundRequests || []).length,
              pendingRefunds: (c.refundRequests || []).filter(r => r.refundStatus === 'pending').length,
              avatarUrl: c.avatarUrl || null,
              verified: c.verified || false,
            });
          }
        });
      }
      // Sort: banned first, then by strike count, then by refund count
      creators.sort((a, b) => {
        if (a.banned !== b.banned) return a.banned ? -1 : 1;
        if (a.payoutsFrozen !== b.payoutsFrozen) return a.payoutsFrozen ? -1 : 1;
        if (a.strikeCount !== b.strikeCount) return b.strikeCount - a.strikeCount;
        return b.pendingRefunds - a.pendingRefunds;
      });
      return ok({ total: creators.length, creators });
    } catch(e) { return err(500, e.message); }
  }

  // ── GET /admin/analytics — platform-wide stats ────────────────────────────────
  if (method === 'GET' && path === '/admin/analytics') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    try {
      const index = await getUserIndex();
      const usernames = (index || []).map(u => u.username).filter(Boolean);
      let totalRevenue = 0, totalViews = 0, totalDrops = 0, totalRefunds = 0;
      let pendingPayouts = 0, bannedCount = 0, frozenCount = 0;
      const refundReasons = {};
      const now = Date.now();
      const HOLD_MS = 3 * 24 * 60 * 60 * 1000;
      for (let i = 0; i < usernames.length; i += 10) {
        const batch = usernames.slice(i, i + 10);
        const results = await Promise.allSettled(batch.map(u => getCreator(u)));
        results.forEach(r => {
          if (r.status !== 'fulfilled' || !r.value) return;
          const c = r.value;
          totalRevenue += c.grossRevenue || 0;
          totalViews   += c.paidViews || 0;
          totalDrops   += (c.creatorDrops || []).length;
          if (c.banned) bannedCount++;
          if (c.payoutsFrozen) frozenCount++;
          (c.refundRequests || []).forEach(req => {
            totalRefunds++;
            const r2 = req.reason || req.refundReason || 'Unknown';
            refundReasons[r2] = (refundReasons[r2] || 0) + 1;
          });
          (c.sales || []).forEach(s => {
            if ((s.earnedAt || 0) + HOLD_MS > now) pendingPayouts += s.amount * 0.80;
          });
        });
      }
      const topReasons = Object.entries(refundReasons).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([r,c])=>({reason:r,count:c}));
      return ok({ totalRevenue, totalViews, totalDrops, totalRefunds, pendingPayouts: +pendingPayouts.toFixed(2), bannedCount, frozenCount, creatorCount: usernames.length, topRefundReasons: topReasons });
    } catch(e) { return err(500, e.message); }
  }

  // ── POST /admin/forward-to-creator — send refund dispute to creator for review ──
  if (method === 'POST' && path === '/admin/forward-to-creator') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, refundId } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    const req2 = (creator.refundRequests || []).find(r => String(r.id) === String(refundId));
    if (!req2) return err(404, 'Refund request not found');
    // Change status to pending so creator sees it in their queue
    req2.refundStatus = 'pending';
    req2.routedTo = 'creator';
    req2.creatorDeadline = Date.now() + 48 * 60 * 60 * 1000;
    req2.forwardedAt = Date.now();
    await putCreator(creator);
    // Notify creator via email
    if (creator.email) {
      try {
        await sendEmail(
          creator.email,
          'Refund dispute — your response needed — PlayOnce',
          `Hi @${creator.username},

A viewer has requested a refund for your drop "${req2.title || req2.dropId}".

Amount: $${req2.price || 0}
Reason: ${req2.reason}

Please log into your PlayOnce account and approve or deny this request within 48 hours. If you do not respond, the refund will be automatically approved.

PlayOnce Support`
        );
      } catch(e) {}
    }
    notify('Refund forwarded to @' + creatorUsername, `Drop: ${req2.title}
Amount: $${req2.price}`, '📨').catch(() => {});
    return ok({ status: 'ok' });
  }

  // ── POST /report-problem — store ticket in S3 + notify ─────────────────────
  if (method === 'POST' && path === '/report-problem') {
    const { username, email, message, type } = body;
    if (!message) return err(400, 'Message required');
    // Load or create ticket store
    let tickets = [];
    try {
      const r = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'data/support-tickets.json' }));
      tickets = JSON.parse(await r.Body.transformToString());
    } catch(e) { tickets = []; }
    const ticket = {
      id: 'TKT_' + Date.now(),
      username: username || 'anonymous',
      email: email || '',
      type: type || 'general',
      message,
      status: 'open',
      createdAt: Date.now(),
      resolvedAt: null,
      adminNote: null,
    };
    tickets.unshift(ticket); // newest first
    // Keep last 500 tickets max
    if (tickets.length > 500) tickets = tickets.slice(0, 500);
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET, Key: 'data/support-tickets.json',
      Body: JSON.stringify(tickets), ContentType: 'application/json',
    }));
    // Notify via Slack + email
    const typeLabel = { refund: '💸 Refund Request', technical: '⚙️ Technical', copyright: '⚠️ Copyright', general: '💬 General' }[type] || '💬 Report';
    notify(typeLabel + ' from @' + (username || 'anonymous'), message, '📣').catch(() => {});
    return ok({ status: 'ok', ticketId: ticket.id });
  }

  // ── GET /admin/tickets — list support tickets ─────────────────────────────────
  if (method === 'GET' && path === '/admin/tickets') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || qs.key || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    let tickets = [];
    try {
      const r = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'data/support-tickets.json' }));
      tickets = JSON.parse(await r.Body.transformToString());
    } catch(e) { tickets = []; }
    const status = qs.status || 'open';
    const filtered = status === 'all' ? tickets : tickets.filter(t => t.status === status);
    return ok({ tickets: filtered, total: tickets.length, open: tickets.filter(t => t.status === 'open').length });
  }

  // ── POST /admin/ticket-resolve — mark ticket resolved with a note ─────────────
  if (method === 'POST' && path === '/admin/ticket-resolve') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { ticketId, adminNote } = body;
    let tickets = [];
    try {
      const r = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: 'data/support-tickets.json' }));
      tickets = JSON.parse(await r.Body.transformToString());
    } catch(e) { return err(404, 'No tickets found'); }
    const ticket = tickets.find(t => t.id === ticketId);
    if (!ticket) return err(404, 'Ticket not found');
    ticket.status = 'resolved';
    ticket.resolvedAt = Date.now();
    ticket.adminNote = adminNote || '';
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET, Key: 'data/support-tickets.json',
      Body: JSON.stringify(tickets), ContentType: 'application/json',
    }));
    return ok({ status: 'ok' });
  }

  // ── POST /account/delete ──────────────────────────────────────────────────────
  if (method === 'POST' && path === '/account/delete') {
    const reqCreator = await getAuth();
    if (!reqCreator) return err(401, 'UNAUTHORIZED');
    const adminEmail = process.env.ADMIN_EMAIL || process.env.SES_FROM_EMAIL;
    if (adminEmail) {
      try {
        await sendEmail(adminEmail, 'Account deletion request — @' + reqCreator.username + ' — PlayOnce',
          'Creator @' + reqCreator.username + ' (' + (reqCreator.email || 'no email') + ') has requested account deletion.\n\nTo delete: remove their S3 file at data/users/' + reqCreator.username + '.json and remove from user-index.json.'
        );
      } catch(e) {}
    }
    notify('🗑 Deletion request from @' + reqCreator.username, 'Email: ' + (reqCreator.email || 'none'), '🗑').catch(() => {});
    return ok({ status: 'ok' });
  }

  // ── POST /copyright/claim — viewer submits a copyright claim ─────────────────
  // Hides the drop immediately, notifies platform, logs the claim
  if (method === 'POST' && path === '/copyright/claim') {
    const { creatorUsername, dropName, proof, claimantEmail } = body;
    if (!creatorUsername || !dropName) return err(400, 'Creator username and drop name required');
    const creator = await getCreator(creatorUsername.toLowerCase());
    if (!creator) return err(404, 'Creator not found');

    // Find the drop by title match — exact first, then partial
    const _dn = dropName.toLowerCase().trim();
    let drop  = (creator.drops        || []).find(d => (d.title||'').toLowerCase() === _dn);
    let cdrop = (creator.creatorDrops || []).find(d => (d.title||'').toLowerCase() === _dn);
    // Partial match fallback
    if (!drop)  drop  = (creator.drops        || []).find(d => (d.title||'').toLowerCase().includes(_dn) || _dn.includes((d.title||'').toLowerCase()));
    if (!cdrop) cdrop = (creator.creatorDrops || []).find(d => (d.title||'').toLowerCase().includes(_dn) || _dn.includes((d.title||'').toLowerCase()));
    const dropId = drop?.id || cdrop?.id || null;

    // Hide immediately — review can restore it
    const flagReason = 'Copyright claim from viewer — pending review';
    if (drop)  { drop.live  = false; drop.copyrightHold  = true; drop.copyrightReason  = flagReason; drop.copyrightFlaggedAt  = Date.now(); }
    if (cdrop) { cdrop.live = false; cdrop.copyrightHold = true; cdrop.copyrightReason = flagReason; cdrop.copyrightFlaggedAt = Date.now(); }

    // Log the claim — includes 6h proof deadline for auto-restore
    const PROOF_WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours
    const claimId = Date.now();
    if (!Array.isArray(creator.refundRequests)) creator.refundRequests = [];
    creator.refundRequests.push({
      id: claimId,
      purchaseId: null,
      dropId: String(dropId || dropName),
      title: dropName,
      price: drop?.price || cdrop?.price || 0,
      reason: 'Copyrighted or stolen content',
      refundStatus: 'platform_review',
      routedTo: 'platform',
      submittedAt: claimId,
      proofDeadline: claimId + PROOF_WINDOW_MS, // auto-restore if no admin action by this time
      proofConfirmed: false,  // admin sets true when proof is verified
      creatorUsername: creator.username,
      proof: proof || '',
      claimantEmail: claimantEmail || '',
      isCopyrightClaim: true,
      dropHidden: !!(drop || cdrop),
    });

    await putCreator(creator);

    // Notify platform
    notify(
      '🚨 Copyright claim — drop hidden — @' + creator.username,
      'Drop: ' + dropName + '\nProof: ' + (proof || 'none') + '\nClaimant: ' + (claimantEmail || 'anonymous') + '\nDrop hidden: ' + (!!(drop || cdrop) ? 'Yes' : 'Drop not found by name') + '\nAuto-restores in 6h if no proof confirmed\nReview in admin panel',
      '🚨'
    ).catch(() => {});

    // Email claimant — ask for proof within 6 hours
    const supportEmail2 = process.env.SUPPORT_EMAIL || 'support@playonce.app';
    if (claimantEmail) {
      sendEmail(claimantEmail, 'Your copyright claim has been received — PlayOnce',
        'Thank you for your copyright claim.\n\nDrop: "' + dropName + '"\nCreator: @' + creator.username + '\n\nThe drop has been temporarily hidden while we review your claim.\n\nIMPORTANT: You have 6 hours to submit proof of ownership to ' + supportEmail2 + '\n\nPlease include:\n- Original file or creation date\n- License or ownership document\n- Any other evidence you own this content\n\nIf proof is not received within 6 hours, the drop will be automatically restored.\n\nPlayOnce Support\n' + supportEmail2
      ).catch(() => {});
    }

    // Email creator
    const supportEmail = process.env.SUPPORT_EMAIL || 'support@playonce.app';
    if (creator.email) {
      try {
        await sendEmail(creator.email, 'Your drop has been temporarily hidden — PlayOnce',
          'Hi @' + creator.username + ',\n\nYour drop "' + dropName + '" has been temporarily hidden following a copyright claim.\n\nIMPORTANT: If the claimant does not provide verified proof of ownership within 6 hours, your drop will be automatically restored — no action needed from you.\n\nIf PlayOnce does not receive proof within 6 hours, the claim will be dismissed and your drop restored automatically.\n\nIf you received this in error or need help, contact us at ' + supportEmail + '\n\nPlayOnce Support\n' + supportEmail
        );
        console.log('Copyright notice sent to:', creator.email);
      } catch(e) {
        console.error('Copyright email failed:', e.message, 'to:', creator.email);
      }
    } else {
      console.warn('No email for creator:', creator.username);
    }

    return ok({ status: 'ok', dropHidden: !!(drop || cdrop) });
  }

  // ── POST /drop/delete — atomically remove drop + S3 files ──────────────────
  if (method === 'POST' && path === '/drop/delete') {
    const creator = await getAuth();
    if (!creator) return err(401, 'UNAUTHORIZED');
    const { dropId } = body;
    if (!dropId) return err(400, 'dropId required');

    // Find the drop to get mediaUrl before removing
    const drop = (creator.drops || []).find(d => String(d.id) === String(dropId));
    const before = (creator.drops || []).length;
    creator.drops        = (creator.drops        || []).filter(d => String(d.id) !== String(dropId));
    creator.creatorDrops = (creator.creatorDrops || []).filter(d => String(d.id) !== String(dropId));
    if (creator.drops.length === before) return err(404, 'Drop not found');
    await putCreator(creator);

    // Delete S3 files in background — don't block the response
    (async () => {
      try {
        const username = creator.username;
        // Common file extensions to try
        const exts = ['.mp4', '.mov', '.avi', '.mkv', '.webm', '.m4v'];
        const keysToDelete = [];

        // Video file
        for (const ext of exts) {
          keysToDelete.push('drops/' + username + '/' + dropId + ext);
        }
        // Thumbnail
        keysToDelete.push('thumbnails/' + username + '/' + dropId + '.jpg');
        // HLS files — delete entire directory prefix
        // List all HLS objects first
        const hlsPrefix = 'hls/' + username + '/' + dropId + '/';
        try {
          const listed = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: hlsPrefix }));
          if (listed.Contents) {
            listed.Contents.forEach(obj => keysToDelete.push(obj.Key));
          }
        } catch(e) {}

        // Delete all found files
        await Promise.allSettled(keysToDelete.map(key =>
          s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }))
        ));
        console.log('S3 files deleted for drop:', dropId, '— keys attempted:', keysToDelete.length);
      } catch(e) {
        console.error('S3 delete error for drop', dropId, ':', e.message);
      }
    })();

    return ok({ status: 'ok', deleted: dropId });
  }

  // ── POST /stripe/webhook — Stripe notifies us of payment events ─────────────
  // This is the reliable payment recording path — doesn't depend on the client
  if (method === 'POST' && path === '/stripe/webhook') {
    const sig = event.headers?.['stripe-signature'] || '';
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    const rawBody = event.body || '';

    // Verify Stripe signature if secret is configured
    if (webhookSecret && sig) {
      try {
        // Manual HMAC verification (no Stripe SDK available)
        const crypto = require('crypto');
        const parts = sig.split(',').reduce((acc, part) => {
          const [k, v] = part.split('=');
          acc[k] = v;
          return acc;
        }, {});
        const timestamp = parts.t;
        const expected = crypto
          .createHmac('sha256', webhookSecret)
          .update(timestamp + '.' + rawBody)
          .digest('hex');
        if (expected !== parts.v1) return err(400, 'Invalid signature');
      } catch(e) { return err(400, 'Signature check failed'); }
    }

    let stripeEvent;
    try { stripeEvent = JSON.parse(rawBody); } catch(e) { return err(400, 'Invalid JSON'); }

    // Handle payment_intent.succeeded — record sale reliably
    if (stripeEvent.type === 'payment_intent.succeeded') {
      const intent = stripeEvent.data?.object;
      if (!intent) return ok({ received: true });
      const creatorUsername = intent.metadata?.creatorUsername;
      const dropId          = intent.metadata?.dropId;
      const amount          = intent.amount / 100; // Stripe uses cents
      if (!creatorUsername || !dropId) return ok({ received: true }); // not a drop payment
      try {
        const creator = await getCreator(creatorUsername);
        if (creator) {
          // Check if already recorded (idempotency — Stripe can send duplicates)
          const alreadyRecorded = (creator.sales || []).find(s => s.intentId === intent.id);
          if (!alreadyRecorded) {
            creator.grossRevenue = (creator.grossRevenue || 0) + amount;
            creator.paidViews    = (creator.paidViews    || 0) + 1;
            if (!Array.isArray(creator.sales)) creator.sales = [];
            creator.sales.push({
              amount, dropId: String(dropId),
              earnedAt: Date.now(),
              intentId: intent.id,
              purchaseId: intent.metadata?.purchaseId || null,
              source: 'webhook'
            });
            const drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
            const cdrop = (creator.creatorDrops  || []).find(d => String(d.id) === String(dropId));
            if (drop)  drop.views  = (drop.views  || 0) + 1;
            if (cdrop) cdrop.views = (cdrop.views || 0) + 1;
            await putCreator(creator);
            const dropTitle = drop?.title || cdrop?.title || dropId;
            notify('💰 Payment confirmed (webhook) — $' + amount + ' USD',
              'Creator: @' + creatorUsername + '\nDrop: ' + dropTitle, '💰').catch(() => {});
          }
        }
      } catch(e) { console.error('Webhook payment recording failed:', e.message); }
    }

    // Handle charge.refunded — mark refund complete
    if (stripeEvent.type === 'charge.refunded') {
      const charge  = stripeEvent.data?.object;
      const intentId = charge?.payment_intent;
      if (intentId) {
        try {
          const index = await getUserIndex();
          for (const u of (index || [])) {
            const c = await getCreator(u.username);
            if (!c) continue;
            const sale = (c.sales || []).find(s => s.intentId === intentId);
            if (sale) {
              // Mark the sale as refunded
              sale.refunded = true; sale.refundedAt = Date.now();
              const req = (c.refundRequests || []).find(r => r.intentId === intentId);
              if (req && req.refundStatus !== 'approved') {
                req.refundStatus = 'approved'; req.resolvedAt = Date.now(); req.resolvedBy = 'stripe_webhook';
              }
              await putCreator(c); break;
            }
          }
        } catch(e) { console.error('Webhook refund recording failed:', e.message); }
      }
    }

    return ok({ received: true });
  }

  // ── GET /ping — keep Lambda warm ──────────────────────────────────────────────
  if (method === 'GET' && path === '/ping') {
    return ok({ status: 'ok', ts: Date.now() });
  }

  // ── POST /admin/test-expire-drop — set uploadedAt to 4 days ago for testing ──
  if (method === 'POST' && path === '/admin/test-expire-drop') {
    const adminSecret = process.env.ADMIN_SECRET;
    const provided = event.headers?.['x-admin-key'] || body.adminKey || '';
    if (!adminSecret || provided !== adminSecret) return err(403, 'FORBIDDEN');
    const { creatorUsername, dropId } = body;
    const creator = await getCreator(creatorUsername);
    if (!creator) return err(404, 'Creator not found');
    const FOUR_DAYS_AGO = Date.now() - (4 * 24 * 60 * 60 * 1000);
    const drop  = (creator.drops        || []).find(d => String(d.id) === String(dropId));
    const cdrop = (creator.creatorDrops || []).find(d => String(d.id) === String(dropId));
    if (!drop && !cdrop) return err(404, 'Drop not found');
    if (drop)  { drop.uploadedAt  = FOUR_DAYS_AGO; delete drop.scheduledAt; }
    if (cdrop) { cdrop.uploadedAt = FOUR_DAYS_AGO; delete cdrop.scheduledAt; }
    await putCreator(creator);
    return ok({ status: 'ok', uploadedAt: FOUR_DAYS_AGO, drop: drop?.title || cdrop?.title });
  }

  return err(404, 'NOT FOUND');
};