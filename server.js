/* ============================================================
   VIRA SERVER — Real Backend (Single File)
   اجرا:  node vira-server.js
   نصب:   npm i express better-sqlite3 bcryptjs jsonwebtoken cors helmet express-rate-limit multer ws nanoid dotenv
   ============================================================ */
'use strict';

const express      = require('express');
const http         = require('http');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');
const helmet       = require('helmet');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');
const multer       = require('multer');
const { WebSocketServer } = require('ws');
const { nanoid }   = require('nanoid');
const Database     = require('better-sqlite3');

/* ---------- تنظیمات ---------- */
const PORT          = process.env.PORT || 3000;
const IS_PROD       = process.env.NODE_ENV === 'production';
const JWT_SECRET    = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
if (IS_PROD && !process.env.JWT_SECRET) console.warn('⚠️  JWT_SECRET تنظیم نشده؛ با هر ری‌استارت همه لاگین‌ها پرید.');
const JWT_EXPIRES   = process.env.JWT_EXPIRES || '30d';
const ADMIN_USER    = (process.env.ADMIN_USER || 'dev').toLowerCase();
const ADMIN_PASS    = process.env.ADMIN_PASS || '1';
if (IS_PROD && (!process.env.ADMIN_PASS || ADMIN_PASS.length < 8)) {
  console.error('❌ در حالت production باید ADMIN_PASS (حداقل ۸ کاراکتر) در Environment تنظیم شود.');
  process.exit(1);
}
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 60);
const DATA_DIR      = process.env.DATA_DIR || path.join(__dirname, 'vira-data');
const UPLOAD_DIR    = path.join(DATA_DIR, 'uploads');
const PUBLIC_DIR    = path.join(__dirname, 'public'); // فقط این پوشه عمومی است (نه کد سرور و دیتابیس)

if (!fs.existsSync(DATA_DIR))  fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- دیتابیس SQLite ---------- */
const db = new Database(path.join(DATA_DIR, 'vira.db'));
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  username   TEXT PRIMARY KEY,
  password   TEXT,
  is_admin   INTEGER DEFAULT 0,
  data       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id         TEXT PRIMARY KEY,
  author     TEXT NOT NULL,
  data       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_author  ON posts(author);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE TABLE IF NOT EXISTS messages (
  id         TEXT PRIMARY KEY,
  sender     TEXT NOT NULL,
  receiver   TEXT NOT NULL,
  data       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_from ON messages(sender);
CREATE INDEX IF NOT EXISTS idx_msg_to   ON messages(receiver);
CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(created_at DESC);
CREATE TABLE IF NOT EXISTS stories (
  id         TEXT PRIMARY KEY,
  author     TEXT NOT NULL,
  data       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stories_author ON stories(author);
CREATE TABLE IF NOT EXISTS reports (
  id         TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
  k          TEXT PRIMARY KEY,
  v          TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id         TEXT PRIMARY KEY,
  owner      TEXT NOT NULL,
  mime       TEXT NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`);

/* ---------- JWT / پسورد ---------- */
const sign    = p => jwt.sign(p, JWT_SECRET, { expiresIn: JWT_EXPIRES });
const verify  = t => { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };
const hashPw  = pw => bcrypt.hash(pw, 10);
const cmpPw   = (pw, h) => h ? bcrypt.compare(pw, h) : Promise.resolve(false);

/* ---------- ادمین پیش‌فرض ---------- */
(async () => {
  const row = db.prepare('SELECT username FROM users WHERE username=?').get(ADMIN_USER);
  if (!row) {
    const pw = await hashPw(ADMIN_PASS);
    const data = {
      username: ADMIN_USER,
      displayName: 'مدیر ویرا',
      bio: 'حساب رسمی مدیریت ویرا',
      avatarColor: '#3E63FF',
      following: [],
      giftsReceived: [],
      roles: [],
      verifiedColor: '#1D9BF0',
      verifiedSize: 23,
      coins: 0,
      createdAt: Date.now()
    };
    db.prepare('INSERT INTO users (username,password,is_admin,data,created_at) VALUES (?,?,?,?,?)')
      .run(ADMIN_USER, pw, 1, JSON.stringify(data), Date.now());
    console.log(`✅ Admin created: @${ADMIN_USER} / pass: ${ADMIN_PASS}`);
  }
})();

/* ---------- Express ---------- */
const app = express();
const server = http.createServer(app);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

/* ---------- Rate limiting ---------- */
const apiLimiter = rateLimit({ windowMs: 60_000, max: 600, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15*60_000, max: 40, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too_many_requests' } });
app.use('/api', apiLimiter);

/* ---------- کمک‌ها ---------- */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'unauthorized' });
  const p = verify(t);
  if (!p) return res.status(401).json({ error: 'invalid_token' });
  req.user = p;
  next();
}
function optAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  req.user = t ? verify(t) : null;
  next();
}
function isPanelUser(username) {
  if (!username) return false;
  if (username === ADMIN_USER) return true;
  const row = db.prepare('SELECT data FROM users WHERE username=?').get(username);
  if (!row) return false;
  const u = JSON.parse(row.data);
  return !!(u.panelAccess && !u.suspended);
}
function requirePanel(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  if (req.user.isAdmin || isPanelUser(req.user.username)) return next();
  return res.status(403).json({ error: 'forbidden' });
}
function getUser(username) {
  const row = db.prepare('SELECT data,is_admin FROM users WHERE username=?').get(username);
  if (!row) return null;
  return { ...JSON.parse(row.data), isAdmin: !!row.is_admin };
}
function upsertUser(username, data, passwordHash, isAdmin) {
  const now = Date.now();
  const existing = db.prepare('SELECT username FROM users WHERE username=?').get(username);
  if (existing) {
    if (passwordHash) {
      db.prepare('UPDATE users SET password=?, is_admin=?, data=? WHERE username=?')
        .run(passwordHash, isAdmin ? 1 : 0, JSON.stringify(data), username);
    } else {
      db.prepare('UPDATE users SET is_admin=?, data=? WHERE username=?')
        .run(isAdmin ? 1 : 0, JSON.stringify(data), username);
    }
  } else {
    db.prepare('INSERT INTO users (username,password,is_admin,data,created_at) VALUES (?,?,?,?,?)')
      .run(username, passwordHash || '', isAdmin ? 1 : 0, JSON.stringify(data), now);
  }
}

/* ============================================================
   AUTH ROUTES
   ============================================================ */
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });
  const uname = String(username).trim().toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(uname)) return res.status(400).json({ error: 'invalid_username' });
  if (String(password).length < 4) return res.status(400).json({ error: 'weak_password' });
  if (uname === ADMIN_USER) return res.status(409).json({ error: 'reserved' });
  const exists = db.prepare('SELECT username FROM users WHERE username=?').get(uname);
  if (exists) return res.status(409).json({ error: 'taken' });

  const pw = await hashPw(password);
  const data = {
    username: uname,
    displayName: uname,
    bio: '',
    tagline: '',
    verified: false,
    premium: false,
    role: null,
    avatarColor: '#3E63FF',
    following: [],
    pinnedPostId: null,
    createdAt: Date.now(),
    coins: 1,
    giftsReceived: [],
    blockedUsers: []
  };
  upsertUser(uname, data, pw, false);
  const token = sign({ username: uname, isAdmin: false });
  res.json({ ok: true, token, username: uname, isAdmin: false });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });
  const uname = String(username).trim().toLowerCase();
  const row = db.prepare('SELECT password,is_admin,data FROM users WHERE username=?').get(uname);
  if (!row) return res.status(401).json({ error: 'bad_credentials' });
  const ok = await cmpPw(password, row.password);
  if (!ok) return res.status(401).json({ error: 'bad_credentials' });
  const u = JSON.parse(row.data);
  if (u.suspended) return res.status(403).json({ error: 'suspended' });
  const token = sign({ username: uname, isAdmin: !!row.is_admin });
  res.json({ ok: true, token, username: uname, isAdmin: !!row.is_admin });
});

app.get('/api/me', auth, (req, res) => {
  const u = getUser(req.user.username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true, user: u });
});

app.post('/api/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 4) return res.status(400).json({ error: 'weak_password' });
  const row = db.prepare('SELECT password FROM users WHERE username=?').get(req.user.username);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const ok = await cmpPw(oldPassword, row.password);
  if (!ok) return res.status(403).json({ error: 'bad_password' });
  const pw = await hashPw(newPassword);
  db.prepare('UPDATE users SET password=? WHERE username=?').run(pw, req.user.username);
  res.json({ ok: true });
});

/* ============================================================
   USERS ROUTES
   ============================================================ */
app.get('/api/users', optAuth, (req, res) => {
  const rows = db.prepare('SELECT username, data, is_admin FROM users').all();
  const users = {};
  for (const r of rows) {
    const u = JSON.parse(r.data);
    users[r.username] = u;
  }
  res.json({ ok: true, users });
});

app.get('/api/users/:username', optAuth, (req, res) => {
  const u = getUser(req.params.username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true, user: u });
});

app.put('/api/users/me', auth, (req, res) => {
  const cur = getUser(req.user.username);
  if (!cur) return res.status(404).json({ error: 'not_found' });
  const patch = req.body || {};
  const allowed = ['displayName','bio','tagline','avatarColor','avatarImage','avatarFull',
    'following','pinnedPostId','pinnedGifts','giftsReceived','coins','blockedUsers',
    'nameFx','avatarRing','ghostStory','statsOverride','badgeOrder','badgeGap',
    'premium','premiumUntil','role','panelAccess','verified','verifiedColor',
    'verifiedSize','verifiedTick','verifiedStyle','verifiedGlow','verifiedAnim',
    'verifiedImage','verifiedTitle','verifiedMsg','chatBg','uiPrefs'];
  const next = { ...cur };
  for (const k of allowed) if (k in patch) next[k] = patch[k];
  if (req.user.isAdmin) next.username = req.user.username;
  upsertUser(req.user.username, next, null, req.user.isAdmin);
  res.json({ ok: true, user: next });
});

/* پروفایل ادمین به عنوان یک کاربر واقعی (برای ویترین) */
app.get('/api/admin/profile', optAuth, (req, res) => {
  const u = getUser(ADMIN_USER);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true, user: u });
});

/* ============================================================
   POSTS ROUTES
   ============================================================ */
app.get('/api/posts', optAuth, (req, res) => {
  const limit = Math.min(500, Number(req.query.limit) || 200);
  const rows = db.prepare('SELECT id, data FROM posts ORDER BY created_at DESC LIMIT ?').all(limit);
  const posts = rows.map(r => JSON.parse(r.data));
  res.json({ ok: true, posts });
});

app.get('/api/posts/:id', optAuth, (req, res) => {
  const row = db.prepare('SELECT id, data FROM posts WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true, post: JSON.parse(row.data) });
});

app.post('/api/posts', auth, (req, res) => {
  const p = req.body || {};
  if (!p || !p.id) return res.status(400).json({ error: 'invalid' });
  p.author = p.author || req.user.username;
  if (p.author !== req.user.username && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  p.createdAt = p.createdAt || Date.now();
  db.prepare('INSERT OR REPLACE INTO posts (id,author,data,created_at) VALUES (?,?,?,?)')
    .run(p.id, p.author, JSON.stringify(p), p.createdAt);
  broadcast({ type: 'post:new', post: p });
  res.json({ ok: true, post: p });
});

app.put('/api/posts/:id', auth, (req, res) => {
  const row = db.prepare('SELECT data, author FROM posts WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.author !== req.user.username && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const next = { ...JSON.parse(row.data), ...req.body, id: req.params.id };
  db.prepare('UPDATE posts SET data=? WHERE id=?').run(JSON.stringify(next), req.params.id);
  broadcast({ type: 'post:update', post: next });
  res.json({ ok: true, post: next });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const row = db.prepare('SELECT author FROM posts WHERE id=?').get(req.params.id);
  if (!row) return res.json({ ok: true });
  if (row.author !== req.user.username && !req.user.isAdmin && !isPanelUser(req.user.username)) {
    return res.status(403).json({ error: 'forbidden' });
  }
  db.prepare('DELETE FROM posts WHERE id=?').run(req.params.id);
  broadcast({ type: 'post:delete', id: req.params.id });
  res.json({ ok: true });
});

/* لایک / آنلایک */
app.post('/api/posts/:id/like', auth, (req, res) => {
  const row = db.prepare('SELECT data FROM posts WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const p = JSON.parse(row.data);
  p.likes = Array.isArray(p.likes) ? p.likes : [];
  const i = p.likes.indexOf(req.user.username);
  if (i >= 0) p.likes.splice(i, 1); else p.likes.push(req.user.username);
  db.prepare('UPDATE posts SET data=? WHERE id=?').run(JSON.stringify(p), req.params.id);
  res.json({ ok: true, likes: p.likes });
});

/* بازدید پست */
app.post('/api/posts/:id/view', auth, (req, res) => {
  const key = `pview:${req.params.id}:${req.user.username}`;
  db.prepare('INSERT OR REPLACE INTO kv (k,v,updated_at) VALUES (?,?,?)')
    .run(key, String(Date.now()), Date.now());
  res.json({ ok: true });
});

app.get('/api/posts/:id/views', (req, res) => {
  const rows = db.prepare("SELECT k FROM kv WHERE k LIKE ?").all(`pview:${req.params.id}:%`);
  res.json({ ok: true, count: rows.length });
});

/* ============================================================
   MESSAGES ROUTES
   ============================================================ */
app.get('/api/messages', auth, (req, res) => {
  const me = req.user.username;
  const withUser = req.query.with;
  let rows;
  if (withUser) {
    rows = db.prepare(`
      SELECT id, data FROM messages
      WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
      ORDER BY created_at ASC LIMIT 1000
    `).all(me, withUser, withUser, me);
  } else {
    rows = db.prepare(`
      SELECT id, data FROM messages
      WHERE sender=? OR receiver=?
      ORDER BY created_at ASC LIMIT 3000
    `).all(me, me);
  }
  res.json({ ok: true, messages: rows.map(r => JSON.parse(r.data)) });
});

app.post('/api/messages', auth, (req, res) => {
  const m = req.body || {};
  if (!m || !m.to) return res.status(400).json({ error: 'invalid' });
  const msg = {
    id: m.id || 'm' + Date.now() + nanoid(6),
    from: req.user.username,
    to: m.to,
    text: String(m.text || '').slice(0, 5000),
    media: m.media || null,
    story: m.story || null,
    createdAt: Date.now(),
    read: false,
    reactions: {},
    deletedFor: []
  };
  db.prepare('INSERT INTO messages (id,sender,receiver,data,created_at) VALUES (?,?,?,?,?)')
    .run(msg.id, msg.from, msg.to, JSON.stringify(msg), msg.createdAt);
  broadcast({ type: 'message:new', message: msg });
  res.json({ ok: true, message: msg });
});

app.put('/api/messages/:id', auth, (req, res) => {
  const row = db.prepare('SELECT data, sender FROM messages WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const old = JSON.parse(row.data);
  if (old.from !== req.user.username && old.to !== req.user.username && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const next = { ...old, ...req.body, id: req.params.id };
  db.prepare('UPDATE messages SET data=? WHERE id=?').run(JSON.stringify(next), req.params.id);
  broadcast({ type: 'message:update', message: next });
  res.json({ ok: true, message: next });
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const row = db.prepare('SELECT data, sender FROM messages WHERE id=?').get(req.params.id);
  if (!row) return res.json({ ok: true });
  const m = JSON.parse(row.data);
  if (m.from !== req.user.username && m.to !== req.user.username && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  db.prepare('DELETE FROM messages WHERE id=?').run(req.params.id);
  broadcast({ type: 'message:delete', id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/messages/read', auth, (req, res) => {
  const { with: other } = req.body || {};
  if (!other) return res.status(400).json({ error: 'invalid' });
  const rows = db.prepare('SELECT id,data FROM messages WHERE sender=? AND receiver=?').all(other, req.user.username);
  const upd = db.prepare('UPDATE messages SET data=? WHERE id=?');
  const tx = db.transaction(() => {
    for (const r of rows) {
      const m = JSON.parse(r.data);
      if (!m.read) { m.read = true; upd.run(JSON.stringify(m), r.id); }
    }
  });
  tx();
  broadcast({ type: 'messages:read', by: req.user.username, with: other });
  res.json({ ok: true });
});

/* ============================================================
   STORIES ROUTES
   ============================================================ */
app.get('/api/stories', optAuth, (req, res) => {
  const cutoff = Date.now() - 2 * 24 * 60 * 60 * 1000; // ۴۸ ساعت
  const rows = db.prepare('SELECT id,data FROM stories WHERE created_at>? ORDER BY created_at ASC').all(cutoff);
  res.json({ ok: true, stories: rows.map(r => JSON.parse(r.data)) });
});

app.post('/api/stories', auth, (req, res) => {
  const s = req.body || {};
  if (!s || !s.media) return res.status(400).json({ error: 'invalid' });
  const st = {
    id: s.id || 's' + Date.now() + nanoid(6),
    author: req.user.username,
    media: s.media,
    caption: String(s.caption || '').slice(0, 500),
    createdAt: Date.now(),
    views: [],
    likes: []
  };
  db.prepare('INSERT INTO stories (id,author,data,created_at) VALUES (?,?,?,?)')
    .run(st.id, st.author, JSON.stringify(st), st.createdAt);
  broadcast({ type: 'story:new', story: st });
  res.json({ ok: true, story: st });
});

app.delete('/api/stories/:id', auth, (req, res) => {
  const row = db.prepare('SELECT author FROM stories WHERE id=?').get(req.params.id);
  if (!row) return res.json({ ok: true });
  if (row.author !== req.user.username && !req.user.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  db.prepare('DELETE FROM stories WHERE id=?').run(req.params.id);
  broadcast({ type: 'story:delete', id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/stories/:id/view', auth, (req, res) => {
  const row = db.prepare('SELECT data FROM stories WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const s = JSON.parse(row.data);
  s.views = Array.from(new Set([...(s.views || []), req.user.username]));
  db.prepare('UPDATE stories SET data=? WHERE id=?').run(JSON.stringify(s), req.params.id);
  res.json({ ok: true, views: s.views.length });
});

app.post('/api/stories/:id/like', auth, (req, res) => {
  const row = db.prepare('SELECT data FROM stories WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const s = JSON.parse(row.data);
  s.likes = Array.isArray(s.likes) ? s.likes : [];
  const i = s.likes.indexOf(req.user.username);
  if (i >= 0) s.likes.splice(i, 1); else s.likes.push(req.user.username);
  db.prepare('UPDATE stories SET data=? WHERE id=?').run(JSON.stringify(s), req.params.id);
  res.json({ ok: true, likes: s.likes });
});

/* ============================================================
   REPORTS ROUTES
   ============================================================ */
app.get('/api/reports', auth, requirePanel, (req, res) => {
  const rows = db.prepare('SELECT id,data FROM reports ORDER BY created_at DESC LIMIT 500').all();
  res.json({ ok: true, reports: rows.map(r => JSON.parse(r.data)) });
});

app.post('/api/reports', auth, (req, res) => {
  const r = req.body || {};
  if (!r || !r.type || !r.target || !r.reason) return res.status(400).json({ error: 'invalid' });
  const rep = {
    id: 'r' + Date.now() + nanoid(6),
    type: r.type,
    target: r.target,
    reporter: req.user.username,
    reason: String(r.reason).slice(0, 500),
    createdAt: Date.now(),
    status: 'open'
  };
  db.prepare('INSERT INTO reports (id,data,created_at) VALUES (?,?,?)')
    .run(rep.id, JSON.stringify(rep), rep.createdAt);
  res.json({ ok: true, report: rep });
});

app.put('/api/reports/:id', auth, requirePanel, (req, res) => {
  const row = db.prepare('SELECT data FROM reports WHERE id=?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not_found' });
  const next = { ...JSON.parse(row.data), ...req.body, id: req.params.id };
  db.prepare('UPDATE reports SET data=? WHERE id=?').run(JSON.stringify(next), req.params.id);
  res.json({ ok: true, report: next });
});

/* ============================================================
   KV ROUTES  (سازگار با window.storage app)
   ============================================================ */
app.get('/api/kv', optAuth, (req, res) => {
  const prefix = req.query.prefix || '';
  const values = req.query.values === '1';
  const rows = prefix
    ? db.prepare("SELECT k,v FROM kv WHERE k LIKE ?").all(prefix + '%')
    : db.prepare("SELECT k,v FROM kv").all();
  const keys = rows.map(r => r.k);
  const items = {};
  if (values) for (const r of rows) items[r.k] = r.v;
  res.json({ ok: true, keys, items });
});

app.get('/api/kv/:key', optAuth, (req, res) => {
  const row = db.prepare('SELECT v FROM kv WHERE k=?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true, value: row.v });
});

app.put('/api/kv/:key', optAuth, (req, res) => {
  const { value } = req.body || {};
  if (value === undefined) return res.status(400).json({ error: 'missing_value' });
  db.prepare('INSERT OR REPLACE INTO kv (k,v,updated_at) VALUES (?,?,?)')
    .run(req.params.key, String(value), Date.now());
  res.json({ ok: true });
});

app.delete('/api/kv/:key', optAuth, (req, res) => {
  db.prepare('DELETE FROM kv WHERE k=?').run(req.params.key);
  res.json({ ok: true });
});

/* ============================================================
   UPLOAD (multer)
   ============================================================ */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const id = nanoid(20);
    const ext = path.extname(file.originalname || '').slice(0, 10) || '';
    cb(null, id + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^(image|video|audio)\//.test(file.mimetype);
    cb(null, ok);
  }
});
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  const id = path.basename(req.file.filename);
  db.prepare('INSERT INTO files (id,owner,mime,size,created_at) VALUES (?,?,?,?,?)')
    .run(id, req.user.username, req.file.mimetype, req.file.size, Date.now());
  res.json({ ok: true, id, url: `/uploads/${id}`, mime: req.file.mimetype, size: req.file.size });
});
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', immutable: true }));

/* ============================================================
   ADMIN ROUTES (پنل مدیریت)
   ============================================================ */
app.get('/api/admin/stats', auth, requirePanel, (req, res) => {
  const usersCount    = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const postsCount    = db.prepare('SELECT COUNT(*) c FROM posts').get().c;
  const msgCount      = db.prepare('SELECT COUNT(*) c FROM messages').get().c;
  const storyCount    = db.prepare('SELECT COUNT(*) c FROM stories').get().c;
  const openReports   = db.prepare("SELECT COUNT(*) c FROM reports").get().c;
  const filesCount    = db.prepare('SELECT COUNT(*) c FROM files').get().c;
  res.json({ ok: true, stats: { usersCount, postsCount, msgCount, storyCount, openReports, filesCount } });
});

app.post('/api/admin/suspend', auth, requirePanel, (req, res) => {
  const { username, suspended } = req.body || {};
  if (!username || username === ADMIN_USER) return res.status(400).json({ error: 'invalid' });
  const u = getUser(username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  u.suspended = !!suspended;
  upsertUser(username, u, null, false);
  res.json({ ok: true });
});

app.post('/api/admin/verify', auth, requirePanel, (req, res) => {
  const { username, verified } = req.body || {};
  const u = getUser(username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  u.verified = !!verified;
  upsertUser(username, u, null, username === ADMIN_USER);
  res.json({ ok: true });
});

app.post('/api/admin/premium', auth, requirePanel, (req, res) => {
  const { username, premium, days } = req.body || {};
  const u = getUser(username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  u.premium = !!premium;
  u.premiumUntil = days ? Date.now() + Number(days) * 86400000 : 0;
  upsertUser(username, u, null, username === ADMIN_USER);
  res.json({ ok: true });
});

app.post('/api/admin/panel-access', auth, requirePanel, (req, res) => {
  const { username, panelAccess } = req.body || {};
  if (username === ADMIN_USER) return res.status(400).json({ error: 'invalid' });
  const u = getUser(username);
  if (!u) return res.status(404).json({ error: 'not_found' });
  u.panelAccess = !!panelAccess;
  upsertUser(username, u, null, false);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:username', auth, requirePanel, (req, res) => {
  const target = req.params.username;
  if (target === ADMIN_USER) return res.status(400).json({ error: 'invalid' });
  db.prepare('DELETE FROM users WHERE username=?').run(target);
  db.prepare('DELETE FROM posts WHERE author=?').run(target);
  db.prepare('DELETE FROM messages WHERE sender=? OR receiver=?').run(target, target);
  db.prepare('DELETE FROM stories WHERE author=?').run(target);
  res.json({ ok: true });
});

/* ============================================================
   HEALTH
   ============================================================ */
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/api/health', (req, res) => {
  res.json({ ok: true, name: 'vira-server', time: Date.now(), version: '1.0.0' });
});

/* ============================================================
   STATIC (سرو کردن خود اپ index.html)
   ============================================================ */
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));
app.get('*', (req, res) => {
  // اگر درخواست API نبود، فایل index را برگردان
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads')) {
    return res.status(404).json({ error: 'not_found' });
  }
  const idx = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(idx)) res.sendFile(idx);
  else res.status(404).send('Not Found');
});

/* ============================================================
   WEBSOCKET  —  Real-time (chat, posts, stories)
   ============================================================ */
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Map(); // username -> Set<ws>

wss.on('connection', (ws, req) => {
  let authedUser = null;
  const url = new URL(req.url, 'http://x');
  const token = url.searchParams.get('token') || '';
  const payload = verify(token);
  if (payload) {
    authedUser = payload.username;
    if (!clients.has(authedUser)) clients.set(authedUser, new Set());
    clients.get(authedUser).add(ws);
  }

  ws.on('message', raw => {
    try {
      const msg = JSON.parse(String(raw));
      // heartbeat + typing
      if (msg.type === 'typing' && authedUser) {
        broadcast({ type: 'typing', from: authedUser, to: msg.to });
      }
      if (msg.type === 'ping') ws.send(JSON.stringify({ type: 'pong', t: Date.now() }));
    } catch {}
  });

  ws.on('close', () => {
    if (authedUser && clients.has(authedUser)) {
      clients.get(authedUser).delete(ws);
      if (!clients.get(authedUser).size) clients.delete(authedUser);
    }
  });
});

function broadcast(obj) {
  const data = JSON.stringify(obj);
  for (const set of clients.values()) {
    for (const ws of set) {
      try { if (ws.readyState === 1) ws.send(data); } catch {}
    }
  }
}

/* ============================================================
   START
   ============================================================ */
server.listen(PORT, '0.0.0.0', () => {
  console.log('==============================================');
  console.log(`🚀 VIRA SERVER running`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   WebSocket: ws://localhost:${PORT}/ws`);
  console.log(`   Admin: @${ADMIN_USER}`);
  console.log(`   Data:  ${DATA_DIR}`);
  console.log('==============================================');
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down...');
  server.close(() => process.exit(0));
});