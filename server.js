const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin';

// ── PostgreSQL ────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function dbQuery(sql, params) {
  const client = await pool.connect();
  try { return await client.query(sql, params); }
  finally { client.release(); }
}

// ── Init tables ───────────────────────────────────────────────
async function initDB() {
  await dbQuery(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    team TEXT NOT NULL DEFAULT 'Neutral',
    created_at TIMESTAMP DEFAULT NOW()
  )`, []);

  // Add team column if upgrading from older schema
  await dbQuery(`ALTER TABLE users ADD COLUMN IF NOT EXISTS team TEXT DEFAULT 'Neutral'`, []).catch(function(){});
  await dbQuery(`UPDATE users SET team = 'Neutral' WHERE team IS NULL`, []).catch(function(){});
  await dbQuery(`ALTER TABLE users ALTER COLUMN team SET NOT NULL`, []).catch(function(){});
  await dbQuery(`ALTER TABLE users ALTER COLUMN team SET DEFAULT 'Neutral'`, []).catch(function(){});

  await dbQuery(`CREATE TABLE IF NOT EXISTS predictions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    constituency_id INTEGER NOT NULL,
    party TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, constituency_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`, []);

  await dbQuery(`CREATE TABLE IF NOT EXISTS actual_results (
    constituency_id INTEGER PRIMARY KEY,
    party TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
  )`, []);

  await dbQuery(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`, []);

  await dbQuery(`INSERT INTO settings (key, value) VALUES ('predictions_locked', 'false') ON CONFLICT DO NOTHING`, []);

  // Seed 2021 results if empty
  const existing = await dbQuery('SELECT COUNT(*) as c FROM actual_results', []);
  if (parseInt(existing.rows[0].c) === 0) {
    const results2021 = {
      1:'UDF',2:'UDF',3:'LDF',4:'LDF',5:'LDF',6:'LDF',7:'LDF',8:'LDF',9:'UDF',10:'LDF',
      11:'LDF',12:'LDF',13:'LDF',14:'LDF',15:'LDF',16:'UDF',17:'LDF',18:'UDF',19:'UDF',
      20:'UDF',21:'LDF',22:'LDF',23:'LDF',24:'LDF',25:'LDF',26:'LDF',27:'LDF',28:'LDF',
      29:'LDF',30:'LDF',31:'UDF',32:'LDF',33:'UDF',34:'UDF',35:'LDF',36:'UDF',37:'UDF',
      38:'UDF',39:'UDF',40:'UDF',41:'UDF',42:'UDF',43:'UDF',44:'LDF',45:'UDF',46:'UDF',
      47:'LDF',48:'LDF',49:'LDF',50:'LDF',51:'LDF',52:'LDF',53:'LDF',54:'UDF',55:'LDF',
      56:'UDF',57:'LDF',58:'LDF',59:'LDF',60:'LDF',61:'LDF',62:'LDF',63:'LDF',64:'LDF',
      65:'LDF',66:'LDF',67:'LDF',68:'LDF',69:'LDF',70:'LDF',71:'LDF',72:'UDF',73:'LDF',
      74:'UDF',75:'UDF',76:'UDF',77:'LDF',78:'UDF',79:'LDF',80:'LDF',81:'UDF',82:'UDF',
      83:'UDF',84:'LDF',85:'UDF',86:'UDF',87:'LDF',88:'LDF',89:'LDF',90:'UDF',91:'LDF',
      92:'LDF',93:'Others',94:'UDF',95:'LDF',96:'UDF',97:'LDF',98:'UDF',99:'UDF',100:'LDF',
      101:'LDF',102:'LDF',103:'LDF',104:'LDF',105:'LDF',106:'LDF',107:'Others',108:'UDF',
      109:'LDF',110:'LDF',111:'LDF',112:'UDF',113:'LDF',114:'LDF',115:'LDF',116:'LDF',
      117:'LDF',118:'UDF',119:'LDF',120:'UDF',121:'LDF',122:'Others',123:'Others',
      124:'LDF',125:'LDF',126:'LDF',127:'LDF',128:'LDF',129:'LDF',130:'LDF',131:'LDF',
      132:'LDF',133:'LDF',134:'LDF',135:'LDF',136:'LDF',137:'NDA',138:'LDF',139:'UDF',140:'LDF'
    };
    for (const [cid, party] of Object.entries(results2021)) {
      await dbQuery(
        'INSERT INTO actual_results (constituency_id, party) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [parseInt(cid), party]
      );
    }
    console.log('Seeded 2021 election results');
  }
}

// ── Middleware ────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'kerala-election-2026-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 90 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.username) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Auth ──────────────────────────────────────────────────────
app.post('/api/register', async function(req, res) {
  try {
    var username = (req.body.username || '').trim();
    var password = req.body.password || '';
    var team = ['Vadakkekkara','Kizhakkekkara','Neutral'].includes(req.body.team) ? req.body.team : 'Neutral';
    if (!username || username.length < 3) return res.json({ success: false, error: 'Username must be at least 3 characters.' });
    if (!password || password.length < 4) return res.json({ success: false, error: 'Password must be at least 4 characters.' });
    if (username.toLowerCase() === ADMIN_USER) return res.json({ success: false, error: 'That username is reserved.' });
    var existing = await dbQuery('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return res.json({ success: false, error: 'Username already taken.' });
    var hash = bcrypt.hashSync(password, 10);
    var r = await dbQuery('INSERT INTO users (username, password, team) VALUES ($1, $2, $3) RETURNING id', [username, hash, team]);
    req.session.userId = r.rows[0].id;
    req.session.username = username;
    req.session.isAdmin = false;
    res.json({ success: true, username, isAdmin: false, team });
  } catch(e) { console.error(e); res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/login', async function(req, res) {
  try {
    var username = (req.body.username || '').trim();
    var password = req.body.password || '';
    if (username === ADMIN_USER && password === ADMIN_PASS) {
      req.session.userId = 0;
      req.session.username = ADMIN_USER;
      req.session.isAdmin = true;
      return res.json({ success: true, username: ADMIN_USER, isAdmin: true });
    }
    var r = await dbQuery('SELECT * FROM users WHERE username = $1', [username]);
    if (!r.rows.length) return res.json({ success: false, error: 'Username not found.' });
    var user = r.rows[0];
    if (!bcrypt.compareSync(password, user.password)) return res.json({ success: false, error: 'Incorrect password.' });
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = false;
    res.json({ success: true, username: user.username, isAdmin: false });
  } catch(e) { console.error(e); res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/logout', function(req, res) { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', function(req, res) {
  if (!req.session.username) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username, isAdmin: !!req.session.isAdmin });
});

// ── Lock status (public) ──────────────────────────────────────
app.get('/api/lock-status', async function(req, res) {
  try {
    var r = await dbQuery("SELECT value FROM settings WHERE key = 'predictions_locked'", []);
    res.json({ success: true, locked: r.rows.length ? r.rows[0].value === 'true' : false });
  } catch(e) { res.json({ success: true, locked: false }); }
});

// ── Predictions ───────────────────────────────────────────────
app.get('/api/predictions/mine', requireAuth, async function(req, res) {
  try {
    var r = await dbQuery('SELECT constituency_id, party FROM predictions WHERE user_id = $1', [req.session.userId]);
    var map = {};
    r.rows.forEach(function(row) { map[row.constituency_id] = row.party; });
    res.json({ success: true, predictions: map });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/predictions/save', requireAuth, async function(req, res) {
  try {
    var lock = await dbQuery("SELECT value FROM settings WHERE key = 'predictions_locked'", []);
    if (lock.rows.length && lock.rows[0].value === 'true')
      return res.json({ success: false, error: 'Predictions are locked.' });
    var cid = parseInt(req.body.constituencyId);
    var party = req.body.party;
    if (!cid || cid < 1 || cid > 140) return res.json({ success: false, error: 'Invalid constituency.' });
    if (!['LDF','UDF','NDA','Others'].includes(party)) return res.json({ success: false, error: 'Invalid party.' });
    await dbQuery(
      `INSERT INTO predictions (user_id, constituency_id, party, updated_at) VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, constituency_id) DO UPDATE SET party = EXCLUDED.party, updated_at = NOW()`,
      [req.session.userId, cid, party]
    );
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/predictions/clear', requireAuth, async function(req, res) {
  try {
    var lock = await dbQuery("SELECT value FROM settings WHERE key = 'predictions_locked'", []);
    if (lock.rows.length && lock.rows[0].value === 'true')
      return res.json({ success: false, error: 'Predictions are locked.' });
    await dbQuery('DELETE FROM predictions WHERE user_id = $1 AND constituency_id = $2',
      [req.session.userId, parseInt(req.body.constituencyId)]);
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

// ── Actual Results ────────────────────────────────────────────
app.get('/api/results/actual', async function(req, res) {
  try {
    var r = await dbQuery('SELECT constituency_id, party FROM actual_results', []);
    var map = {};
    r.rows.forEach(function(row) { map[row.constituency_id] = row.party; });
    res.json({ success: true, results: map });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/results/save', requireAdmin, async function(req, res) {
  try {
    var cid = parseInt(req.body.constituencyId);
    var party = req.body.party;
    if (!cid || cid < 1 || cid > 140) return res.json({ success: false, error: 'Invalid.' });
    if (!['LDF','UDF','NDA','Others'].includes(party)) return res.json({ success: false, error: 'Invalid party.' });
    await dbQuery(
      `INSERT INTO actual_results (constituency_id, party, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (constituency_id) DO UPDATE SET party = EXCLUDED.party, updated_at = NOW()`,
      [cid, party]
    );
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/results/clear-one', requireAdmin, async function(req, res) {
  try {
    await dbQuery('DELETE FROM actual_results WHERE constituency_id = $1', [parseInt(req.body.constituencyId)]);
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/results/clear-all', requireAdmin, async function(req, res) {
  try {
    await dbQuery('DELETE FROM actual_results', []);
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

// ── Summary ───────────────────────────────────────────────────
app.get('/api/summary/users', async function(req, res) {
  try {
    var users = await dbQuery('SELECT id, username, team FROM users ORDER BY created_at', []);
    var actual = await dbQuery('SELECT constituency_id, party FROM actual_results', []);
    var actualMap = {};
    actual.rows.forEach(function(r) { actualMap[r.constituency_id] = r.party; });
    var hasActual = actual.rows.length > 0;
    var result = [];
    for (var u of users.rows) {
      var preds = await dbQuery('SELECT constituency_id, party FROM predictions WHERE user_id = $1', [u.id]);
      var totals = { LDF:0, UDF:0, NDA:0, Others:0 };
      var correct = 0;
      preds.rows.forEach(function(p) {
        totals[p.party] = (totals[p.party] || 0) + 1;
        if (hasActual && actualMap[p.constituency_id] && actualMap[p.constituency_id] === p.party) correct++;
      });
      var strikeRate = hasActual ? parseFloat((correct / 140 * 100).toFixed(1)) : null;
      result.push({ username: u.username, team: u.team || 'Neutral', totals, filled: preds.rows.length, correct, strikeRate });
    }
    res.json({ success: true, users: result, hasActual });
  } catch(e) { console.error(e); res.json({ success: false, error: 'Server error.' }); }
});

app.get('/api/summary/user/:username', async function(req, res) {
  try {
    var u = await dbQuery('SELECT id FROM users WHERE username = $1', [req.params.username]);
    if (!u.rows.length) return res.json({ success: false, error: 'User not found.' });
    var preds = await dbQuery('SELECT constituency_id, party FROM predictions WHERE user_id = $1', [u.rows[0].id]);
    var map = {};
    preds.rows.forEach(function(p) { map[p.constituency_id] = p.party; });
    res.json({ success: true, predictions: map });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

// ── Admin ─────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async function(req, res) {
  try {
    var users = await dbQuery('SELECT id, username, team, created_at FROM users ORDER BY created_at', []);
    var result = [];
    for (var u of users.rows) {
      var preds = await dbQuery('SELECT party, COUNT(*) as cnt FROM predictions WHERE user_id = $1 GROUP BY party', [u.id]);
      var totals = { LDF:0, UDF:0, NDA:0, Others:0 };
      var total = 0;
      preds.rows.forEach(function(p) { totals[p.party] = parseInt(p.cnt); total += parseInt(p.cnt); });
      result.push({ id: u.id, username: u.username, team: u.team || 'Neutral', created_at: u.created_at, totals, filled: total });
    }
    res.json({ success: true, users: result });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/admin/delete-user', requireAdmin, async function(req, res) {
  try {
    var uid = parseInt(req.body.userId);
    await dbQuery('DELETE FROM predictions WHERE user_id = $1', [uid]);
    await dbQuery('DELETE FROM users WHERE id = $1', [uid]);
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.get('/api/admin/lock-status', requireAdmin, async function(req, res) {
  try {
    var r = await dbQuery("SELECT value FROM settings WHERE key = 'predictions_locked'", []);
    res.json({ success: true, locked: r.rows.length ? r.rows[0].value === 'true' : false });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.post('/api/admin/set-lock', requireAdmin, async function(req, res) {
  try {
    var locked = req.body.locked ? 'true' : 'false';
    await dbQuery("INSERT INTO settings (key, value) VALUES ('predictions_locked', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [locked]);
    res.json({ success: true, locked: locked === 'true' });
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

// ── Bulk upload ───────────────────────────────────────────────
app.post('/api/admin/bulk-upload', requireAdmin, async function(req, res) {
  try {
    var rows = req.body.rows;
    if (!rows || !Array.isArray(rows)) return res.json({ success: false, error: 'Invalid data.' });
    var valid = ['LDF','UDF','NDA','Others'];
    var results = { success: 0, skipped: 0, errors: [] };

    // Step 1: Validate all rows and collect unique usernames
    var validRows = [];
    var usernameSet = new Set();
    for (var row of rows) {
      var username = (row.username || '').trim();
      var cid = parseInt(row.constituencyId);
      var party = (row.party || '').trim();
      var rowTeam = (row.team || '').trim();
      var team = ['Vadakkekkara','Kizhakkekkara','Neutral'].includes(rowTeam) ? rowTeam : 'Neutral';
      if (!username) { results.errors.push('Row missing username'); results.skipped++; continue; }
      if (!cid || cid < 1 || cid > 140) { results.errors.push(username + ': invalid constituency ' + row.constituencyId); results.skipped++; continue; }
      if (!valid.includes(party)) { results.errors.push(username + ': invalid party ' + party); results.skipped++; continue; }
      validRows.push({ username, cid, party, team });
      usernameSet.add(username);
    }

    if (!validRows.length) return res.json({ success: true, results });

    // Step 2: Batch fetch existing users
    var usernameList = Array.from(usernameSet);
    var existingUsers = await dbQuery(
      'SELECT id, username FROM users WHERE username = ANY($1)',
      [usernameList]
    );
    var userMap = {};
    existingUsers.rows.forEach(function(u) { userMap[u.username] = u.id; });

    // Step 3: Create missing users + update team for all users
    for (var uname of usernameList) {
      var teamForUser = validRows.find(function(r){return r.username===uname;});
      var uteam = (teamForUser && teamForUser.team) ? teamForUser.team : 'Neutral';
      if (!['Vadakkekkara','Kizhakkekkara','Neutral'].includes(uteam)) uteam = 'Neutral';
      if (!userMap[uname]) {
        // New user — create with password = username
        var hash = bcrypt.hashSync(uname, 10);
        var r = await dbQuery(
          'INSERT INTO users (username, password, team) VALUES ($1, $2, $3) ON CONFLICT (username) DO UPDATE SET team=EXCLUDED.team RETURNING id',
          [uname, hash, uteam]
        );
        userMap[uname] = r.rows[0].id;
      } else {
        // Existing user — update their team
        await dbQuery('UPDATE users SET team = $1 WHERE id = $2', [uteam, userMap[uname]]);
      }
    }

    // Step 4: Batch insert predictions in chunks of 500
    var chunkSize = 500;
    for (var i = 0; i < validRows.length; i += chunkSize) {
      var chunk = validRows.slice(i, i + chunkSize);
      var placeholders = [];
      var values = [];
      var idx = 1;
      chunk.forEach(function(row) {
        placeholders.push('($' + idx + ',$' + (idx+1) + ',$' + (idx+2) + ',NOW())');
        values.push(userMap[row.username], row.cid, row.party);
        idx += 3;
      });
      await dbQuery(
        'INSERT INTO predictions (user_id, constituency_id, party, updated_at) VALUES ' +
        placeholders.join(',') +
        ' ON CONFLICT (user_id, constituency_id) DO UPDATE SET party=EXCLUDED.party, updated_at=NOW()',
        values
      );
      results.success += chunk.length;
    }

    res.json({ success: true, results });
  } catch(e) { console.error(e); res.json({ success: false, error: 'Server error: ' + e.message }); }
});

// ── CSV exports ───────────────────────────────────────────────
const CONST_NAMES = {"1":"Manjeshwaram","2":"Kasaragod","3":"Udma","4":"Kanhangad","5":"Thrikkaripur","6":"Payyannur","7":"Kalliasseri","8":"Thaliparamba","9":"Irikkur","10":"Azhikode","11":"Kannur","12":"Dharmadom","13":"Thalassery","14":"Kuthuparamba","15":"Mattannur","16":"Peravoor","17":"Mananthavady","18":"Sulthan Bathery","19":"Kalpetta","20":"Vatakara","21":"Kuttiady","22":"Nadapuram","23":"Koyilandy","24":"Perambra","25":"Balusseri","26":"Elathur","27":"Kozhikode North","28":"Kozhikode South","29":"Beypore","30":"Kunnamangalam","31":"Koduvally","32":"Thiruvambadi","33":"Kondotty","34":"Eranad","35":"Nilambur","36":"Wandoor","37":"Manjeri","38":"Perinthalmanna","39":"Mankada","40":"Malappuram","41":"Vengara","42":"Vallikunnu","43":"Tirurangadi","44":"Tanur","45":"Tirur","46":"Kottakkal","47":"Thavanur","48":"Ponnani","49":"Thrithala","50":"Pattambi","51":"Shornur","52":"Ottappalam","53":"Kongad","54":"Mannarkkad","55":"Malampuzha","56":"Palakkad","57":"Tarur","58":"Chittur","59":"Nenmara","60":"Alathur","61":"Chelakkara","62":"Kunnamkulam","63":"Guruvayoor","64":"Manalur","65":"Wadakkanchery","66":"Ollur","67":"Thrissur","68":"Nattika","69":"Kaipamangalam","70":"Irinjalakuda","71":"Puthukkad","72":"Chalakudy","73":"Kodungallur","74":"Perumbavoor","75":"Angamaly","76":"Aluva","77":"Kalamassery","78":"Paravur","79":"Vypin","80":"Kochi","81":"Thripunithura","82":"Ernakulam","83":"Thrikkakara","84":"Kunnathunad","85":"Piravom","86":"Muvattupuzha","87":"Kothamangalam","88":"Devikulam","89":"Udumbanchola","90":"Thodupuzha","91":"Idukki","92":"Peerumede","93":"Pala","94":"Kaduthuruthy","95":"Kanjirappally","96":"Poonjar","97":"Ettumanoor","98":"Kottayam","99":"Puthuppally","100":"Vaikom","101":"Changanassery","102":"Chirakkadav","103":"Aroor","104":"Cherthala","105":"Ambalapuzha","106":"Alappuzha","107":"Kuttanad","108":"Haripad","109":"Kayamkulam","110":"Mavelikara","111":"Chengannur","112":"Thiruvalla","113":"Ranni","114":"Aranmula","115":"Konni","116":"Adoor","117":"Pandalam","118":"Karunagappally","119":"Chavara","120":"Kundara","121":"Kottarakkara","122":"Kunnathur","123":"Pathanapuram","124":"Punalur","125":"Chadayamangalam","126":"Eravipuram","127":"Kollam","128":"Chathannur","129":"Attingal","130":"Varkala","131":"Chirayinkeezhu","132":"Nedumangad","133":"Vamanapuram","134":"Kattakkada","135":"Kazhakkoottam","136":"Thiruvananthapuram","137":"Nemom","138":"Aruvikkara","139":"Kovalam","140":"Neyyattinkara"};

app.get('/api/admin/csv/predictions', requireAdmin, async function(req, res) {
  try {
    var allPreds = await dbQuery('SELECT u.username, p.constituency_id, p.party FROM predictions p JOIN users u ON p.user_id = u.id ORDER BY u.username, p.constituency_id', []);
    var actual = await dbQuery('SELECT constituency_id, party FROM actual_results', []);
    var actualMap = {};
    actual.rows.forEach(function(r) { actualMap[r.constituency_id] = r.party; });
    var lines = ['Username,Constituency ID,Constituency Name,Party Predicted,Actual Result,Strike'];
    allPreds.rows.forEach(function(p) {
      var act = actualMap[p.constituency_id] || '';
      var strike = act ? (act === p.party ? 'Yes' : 'No') : 'Pending';
      lines.push([p.username, p.constituency_id, CONST_NAMES[p.constituency_id] || '', p.party, act || '—', strike].join(','));
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="predictions.csv"');
    res.send(lines.join('\n'));
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.get('/api/admin/csv/leaderboard', requireAdmin, async function(req, res) {
  try {
    var users = await dbQuery('SELECT id, username, team FROM users ORDER BY username', []);
    var actual = await dbQuery('SELECT constituency_id, party FROM actual_results', []);
    var actualMap = {};
    actual.rows.forEach(function(r) { actualMap[r.constituency_id] = r.party; });
    var hasActual = actual.rows.length > 0;
    var rows = [];
    for (var u of users.rows) {
      var preds = await dbQuery('SELECT constituency_id, party FROM predictions WHERE user_id = $1', [u.id]);
      var correct = 0;
      var totals = {LDF:0,UDF:0,NDA:0,Others:0};
      preds.rows.forEach(function(p) {
        totals[p.party] = (totals[p.party]||0)+1;
        if (hasActual && actualMap[p.constituency_id] === p.party) correct++;
      });
      var sr = hasActual ? (correct/140*100).toFixed(1)+'%' : 'Pending';
      rows.push({ username: u.username, team: u.team||'Neutral', filled: preds.rows.length, correct, sr, totals });
    }
    rows.sort(function(a,b) { return parseFloat(b.sr)-parseFloat(a.sr); });
    var lines = ['Rank,Username,Team,Filled,LDF,UDF,NDA,Others,Correct,Strike Rate'];
    rows.forEach(function(r,i) {
      lines.push([i+1, r.username, r.team||'Neutral', r.filled, r.totals.LDF, r.totals.UDF, r.totals.NDA, r.totals.Others, r.correct, r.sr].join(','));
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="leaderboard.csv"');
    res.send(lines.join('\n'));
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

app.get('/api/admin/csv/actual', requireAdmin, async function(req, res) {
  try {
    var r = await dbQuery('SELECT constituency_id, party FROM actual_results ORDER BY constituency_id', []);
    var lines = ['Constituency ID,Constituency Name,Party'];
    r.rows.forEach(function(row) {
      lines.push([row.constituency_id, CONST_NAMES[row.constituency_id] || '', row.party].join(','));
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="actual_results.csv"');
    res.send(lines.join('\n'));
  } catch(e) { res.json({ success: false, error: 'Server error.' }); }
});

// ── News proxy ────────────────────────────────────────────────
app.get('/api/news', async function(req, res) {
  try {
    var url = 'https://news.google.com/rss/search?q=Kerala+election+2026&hl=en-IN&gl=IN&ceid=IN:en';
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, function(r) {
      var data = '';
      r.on('data', function(chunk) { data += chunk; });
      r.on('end', function() {
        var items = [];
        var re = /<item>[\s\S]*?<title><!\[CDATA\[(.*?)\]\]><\/title>[\s\S]*?<link>(.*?)<\/link>[\s\S]*?<\/item>/g;
        var m;
        while ((m = re.exec(data)) !== null) {
          items.push({ title: m[1].trim(), link: m[2].trim() });
          if (items.length >= 15) break;
        }
        if (!items.length) {
          items = [
            { title: 'Kerala election 2026: Campaign trail heats up across 140 constituencies', link: 'https://news.google.com/search?q=Kerala+election+2026' },
            { title: 'LDF, UDF, NDA finalising candidates for 2026 Kerala Assembly polls', link: 'https://news.google.com/search?q=Kerala+election+2026' },
            { title: 'Kerala 2026 polls: Key seats to watch across all 14 districts', link: 'https://news.google.com/search?q=Kerala+election+2026' }
          ];
        }
        res.json({ success: true, items });
      });
    }).on('error', function() {
      res.json({ success: true, items: [{ title: 'Kerala election 2026 news — click to read more', link: 'https://news.google.com/search?q=Kerala+election+2026' }] });
    });
  } catch(e) { res.json({ success: false, items: [] }); }
});

// ── Start ─────────────────────────────────────────────────────
initDB().then(function() {
  app.listen(PORT, function() {
    console.log('\nKerala Election Predictor running at http://localhost:' + PORT + '\n');
  });
}).catch(function(e) {
  console.error('DB init failed:', e);
  process.exit(1);
});
