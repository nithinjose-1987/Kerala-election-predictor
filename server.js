const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin1234';

// ── Database ──────────────────────────────────────────────────
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

db.serialize(function() {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    constituency_id INTEGER NOT NULL,
    party TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, constituency_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS actual_results (
    constituency_id INTEGER PRIMARY KEY,
    party TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

function dbGet(sql, p) { return new Promise(function(res,rej){ db.get(sql,p,function(e,r){if(e)rej(e);else res(r);}); }); }
function dbAll(sql, p) { return new Promise(function(res,rej){ db.all(sql,p,function(e,r){if(e)rej(e);else res(r||[]);}); }); }
function dbRun(sql, p)  { return new Promise(function(res,rej){ db.run(sql,p,function(e){if(e)rej(e);else res(this);}); }); }

// ── Middleware ────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'kerala-election-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 90 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Auth ──────────────────────────────────────────────────────
app.post('/api/register', async function(req, res) {
  try {
    var username = (req.body.username||'').trim();
    var password = req.body.password||'';
    if (!username || username.length < 3) return res.json({ success:false, error:'Username must be at least 3 characters.' });
    if (!password || password.length < 4) return res.json({ success:false, error:'Password must be at least 4 characters.' });
    if (username.toLowerCase() === ADMIN_USER) return res.json({ success:false, error:'That username is reserved.' });
    var existing = await dbGet('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.json({ success:false, error:'Username already taken.' });
    var hash = bcrypt.hashSync(password, 10);
    var r = await dbRun('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]);
    req.session.userId = r.lastID;
    req.session.username = username;
    req.session.isAdmin = false;
    res.json({ success:true, username:username, isAdmin:false });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/login', async function(req, res) {
  try {
    var username = (req.body.username||'').trim();
    var password = req.body.password||'';
    // Admin login
    if (username === ADMIN_USER && password === ADMIN_PASS) {
      req.session.userId = 0;
      req.session.username = ADMIN_USER;
      req.session.isAdmin = true;
      return res.json({ success:true, username:ADMIN_USER, isAdmin:true });
    }
    var user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.json({ success:false, error:'Username not found.' });
    if (!bcrypt.compareSync(password, user.password)) return res.json({ success:false, error:'Incorrect password.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = false;
    res.json({ success:true, username:user.username, isAdmin:false });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/logout', function(req, res) { req.session.destroy(); res.json({ success:true }); });
app.get('/api/me', function(req, res) {
  if (!req.session.userId && !req.session.isAdmin) return res.json({ loggedIn:false });
  res.json({ loggedIn:true, username:req.session.username, isAdmin:!!req.session.isAdmin });
});

// ── Predictions ───────────────────────────────────────────────
app.get('/api/predictions/mine', requireAuth, async function(req, res) {
  try {
    var rows = await dbAll('SELECT constituency_id, party FROM predictions WHERE user_id = ?', [req.session.userId]);
    var map = {};
    rows.forEach(function(r) { map[r.constituency_id] = r.party; });
    res.json({ success:true, predictions:map });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/predictions/save', requireAuth, async function(req, res) {
  try {
    var cid = parseInt(req.body.constituencyId);
    var party = req.body.party;
    if (!cid || cid < 1 || cid > 140) return res.json({ success:false, error:'Invalid constituency.' });
    if (!['LDF','UDF','NDA','Others'].includes(party)) return res.json({ success:false, error:'Invalid party.' });
    await dbRun(
      `INSERT INTO predictions (user_id, constituency_id, party, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id, constituency_id) DO UPDATE SET party=excluded.party, updated_at=CURRENT_TIMESTAMP`,
      [req.session.userId, cid, party]
    );
    res.json({ success:true });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/predictions/clear', requireAuth, async function(req, res) {
  try {
    await dbRun('DELETE FROM predictions WHERE user_id = ? AND constituency_id = ?', [req.session.userId, parseInt(req.body.constituencyId)]);
    res.json({ success:true });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

// ── Admin ─────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async function(req, res) {
  try {
    var users = await dbAll('SELECT id, username, created_at FROM users', []);
    var result = [];
    for (var i = 0; i < users.length; i++) {
      var u = users[i];
      var rows = await dbAll('SELECT party, COUNT(*) as count FROM predictions WHERE user_id = ? GROUP BY party', [u.id]);
      var totals = { LDF:0, UDF:0, NDA:0, Others:0 };
      var total = 0;
      rows.forEach(function(r) { totals[r.party] = r.count; total += r.count; });
      result.push({ id:u.id, username:u.username, created_at:u.created_at, totals:totals, filled:total });
    }
    res.json({ success:true, users:result });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/admin/delete-user', requireAdmin, async function(req, res) {
  try {
    var userId = parseInt(req.body.userId);
    await dbRun('DELETE FROM predictions WHERE user_id = ?', [userId]);
    await dbRun('DELETE FROM users WHERE id = ?', [userId]);
    res.json({ success:true });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

// ── Actual results (admin sets these) ────────────────────────
app.get('/api/results/actual', async function(req, res) {
  try {
    var rows = await dbAll('SELECT constituency_id, party FROM actual_results', []);
    var map = {};
    rows.forEach(function(r) { map[r.constituency_id] = r.party; });
    res.json({ success:true, results:map });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/results/save', requireAdmin, async function(req, res) {
  try {
    var cid = parseInt(req.body.constituencyId);
    var party = req.body.party;
    if (!cid || cid < 1 || cid > 140) return res.json({ success:false, error:'Invalid.' });
    if (!['LDF','UDF','NDA','Others'].includes(party)) return res.json({ success:false, error:'Invalid party.' });
    await dbRun(
      `INSERT INTO actual_results (constituency_id, party, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(constituency_id) DO UPDATE SET party=excluded.party, updated_at=CURRENT_TIMESTAMP`,
      [cid, party]
    );
    res.json({ success:true });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.post('/api/results/clear', requireAdmin, async function(req, res) {
  try {
    await dbRun('DELETE FROM actual_results WHERE constituency_id = ?', [parseInt(req.body.constituencyId)]);
    res.json({ success:true });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

// ── Summary / Leaderboard ─────────────────────────────────────
app.get('/api/summary/users', async function(req, res) {
  try {
    var users = await dbAll('SELECT id, username FROM users', []);
    var actual = await dbAll('SELECT constituency_id, party FROM actual_results', []);
    var actualMap = {};
    actual.forEach(function(r) { actualMap[r.constituency_id] = r.party; });
    var result = [];
    for (var i = 0; i < users.length; i++) {
      var u = users[i];
      var rows = await dbAll('SELECT constituency_id, party FROM predictions WHERE user_id = ?', [u.id]);
      var totals = { LDF:0, UDF:0, NDA:0, Others:0 };
      var correct = 0;
      rows.forEach(function(r) {
        totals[r.party] = (totals[r.party]||0) + 1;
        if (actualMap[r.constituency_id] && actualMap[r.constituency_id] === r.party) correct++;
      });
      var strikeRate = actual.length > 0 ? Math.round((correct / 140) * 100) : null;
      result.push({ username:u.username, totals:totals, filled:rows.length, correct:correct, strikeRate:strikeRate });
    }
    res.json({ success:true, users:result });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.get('/api/summary/user/:username', async function(req, res) {
  try {
    var user = await dbGet('SELECT id FROM users WHERE username = ?', [req.params.username]);
    if (!user) return res.json({ success:false, error:'User not found.' });
    var rows = await dbAll('SELECT constituency_id, party FROM predictions WHERE user_id = ?', [user.id]);
    var map = {};
    rows.forEach(function(r) { map[r.constituency_id] = r.party; });
    res.json({ success:true, predictions:map });
  } catch(e) { res.json({ success:false, error:'Server error.' }); }
});

app.listen(PORT, function() {
  console.log('\nKerala Election Predictor running at http://localhost:' + PORT + '\n');
});
