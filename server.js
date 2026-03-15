require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

// ─────────────────────────────────────────────
// API REGISTRY — Future mein bas yahan add karo
// ─────────────────────────────────────────────
// type       : unique key type identifier (stored in DB)
// label      : display name
// prefix     : API key prefix
// route      : public endpoint
// paramName  : query param name
// envKey     : process.env key for upstream URL
// description: shown in admin panel
// asyncHandler: custom handler (optional, default = simple proxy)

const API_REGISTRY = [
  {
    type: "number",
    label: "Number Lookup",
    prefix: "ak_",
    route: "/lookup",
    paramName: "number",
    envKey: "UPSTREAM_API_URL",
    description: "Phone number information lookup",
    icon: "📞",
  },
  {
    type: "rto",
    label: "RTO Lookup",
    prefix: "rto_",
    route: "/rto",
    paramName: "rc",
    envKey: "UPSTREAM_RTO_API_URL",
    description: "Vehicle registration / RTO details",
    icon: "🚗",
  },
  {
    type: "image",
    label: "Logo/Image Generator",
    prefix: "img_",
    route: "/generate",
    paramName: "prompt",
    envKey: "UPSTREAM_IMAGE_API_URL",
    description: "AI logo & image generation",
    icon: "🎨",
    asyncGenerate: true, // special two-step flow
    checkEnvKey: "UPSTREAM_IMAGE_CHECK_URL",
  },
];

// ─────────────────────────────────────────────
// MONGODB SCHEMAS
// ─────────────────────────────────────────────

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, default: "superadmin" },
});

const ApiKeySchema = new mongoose.Schema({
  keyType: {
    type: String,
    enum: API_REGISTRY.map((a) => a.type),
    default: "number",
  },
  key: { type: String, unique: true, required: true },
  label: { type: String, default: "" },
  createdBy: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  usageCount: { type: Number, default: 0 },
  usageLimit: { type: Number, default: null },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: null },
});

const Admin = mongoose.model("Admin", AdminSchema);
const ApiKey = mongoose.model("ApiKey", ApiKeySchema);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function generateApiKey(type = "number") {
  const api = API_REGISTRY.find((a) => a.type === type);
  const prefix = api ? api.prefix : "ak_";
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = prefix;
  for (let i = 0; i < 32; i++)
    key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

function authMiddleware(req, res, next) {
  const token =
    req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function superAdminOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username)) {
    return res.status(403).json({ error: "Super admin access required" });
  }
  next();
}

async function validateApiKey(apiKey, requiredType) {
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return { error: "Invalid API key", status: 401 };
  if (!keyDoc.isActive) return { error: "API key is disabled", status: 403 };
  if (keyDoc.keyType !== requiredType)
    return {
      error: `This key is not authorized for ${requiredType} lookups`,
      status: 403,
    };
  if (keyDoc.expiresAt < new Date())
    return { error: "API key expired", status: 403 };
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit)
    return { error: "API key usage limit reached", status: 429 };
  return { keyDoc };
}

async function incrementUsage(keyId) {
  await ApiKey.findByIdAndUpdate(keyId, {
    $inc: { usageCount: 1 },
    lastUsedAt: new Date(),
  });
}

// ─────────────────────────────────────────────
// HTML HELPERS
// ─────────────────────────────────────────────

const CSS_VARS = `
  :root {
    --bg: #050a14;
    --surface: #0d1526;
    --surface2: #131f35;
    --border: #1e2e4a;
    --border2: #243450;
    --accent: #3b82f6;
    --accent2: #6366f1;
    --accent3: #06b6d4;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --text: #e2e8f0;
    --text2: #94a3b8;
    --text3: #64748b;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
  }
`;

const BASE_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{background:var(--bg);font-family:'Space Grotesk',sans-serif;color:var(--text);min-height:100vh}
  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:var(--surface)}
  ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
  a{color:var(--accent);text-decoration:none}

  /* Topbar */
  .topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100;backdrop-filter:blur(8px)}
  .topbar-brand{display:flex;align-items:center;gap:10px}
  .topbar-brand h1{font-size:1rem;font-weight:700;letter-spacing:-.01em}
  .topbar-brand .ver{font-size:.7rem;background:var(--border2);color:var(--text2);padding:2px 8px;border-radius:999px;font-family:var(--mono)}
  .topbar-actions{display:flex;align-items:center;gap:10px}

  /* Container */
  .container{max-width:1140px;margin:0 auto;padding:28px 20px}

  /* Cards */
  .card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px;margin-bottom:20px}
  .card-title{font-size:.95rem;font-weight:600;color:var(--text);margin-bottom:18px;display:flex;align-items:center;gap:8px}
  .card-title span{font-size:1.1rem}

  /* Tabs */
  .tabs{display:flex;gap:6px;margin-bottom:24px;flex-wrap:wrap}
  .tab{padding:8px 18px;border-radius:8px;border:1px solid var(--border);background:transparent;color:var(--text2);cursor:pointer;font-size:.875rem;font-family:'Space Grotesk',sans-serif;font-weight:500;transition:all .2s}
  .tab:hover{border-color:var(--border2);color:var(--text)}
  .tab.active{background:var(--accent);border-color:var(--accent);color:#fff}
  .panel{display:none}.panel.active{display:block}

  /* Grid */
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
  .grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}

  /* Forms */
  label{display:block;color:var(--text2);font-size:.8rem;margin-bottom:6px;margin-top:14px;font-weight:500;letter-spacing:.02em;text-transform:uppercase}
  input,select,textarea{width:100%;padding:10px 13px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.9rem;font-family:'Space Grotesk',sans-serif;transition:border-color .2s}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
  select option{background:var(--surface)}

  /* Buttons */
  .btn{padding:9px 20px;border:none;border-radius:8px;cursor:pointer;font-size:.875rem;font-weight:600;font-family:'Space Grotesk',sans-serif;transition:all .2s;display:inline-flex;align-items:center;gap:6px}
  .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#2563eb;transform:translateY(-1px)}
  .btn-green{background:var(--green);color:#fff}.btn-green:hover{background:#059669}
  .btn-danger{background:var(--red);color:#fff;font-size:.8rem;padding:5px 12px}.btn-danger:hover{background:#dc2626}
  .btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text2)}.btn-ghost:hover{border-color:var(--border2);color:var(--text)}
  .btn-copy{background:var(--surface2);color:var(--text2);font-size:.75rem;padding:3px 10px;border:1px solid var(--border);border-radius:5px;cursor:pointer;font-family:var(--mono);transition:all .2s}
  .btn-copy:hover{background:var(--border);color:var(--text)}

  /* Table */
  .table-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}
  table{width:100%;border-collapse:collapse;font-size:.82rem;min-width:600px}
  th{text-align:left;padding:11px 14px;color:var(--text3);border-bottom:1px solid var(--border);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;background:var(--surface2)}
  td{padding:11px 14px;border-bottom:1px solid var(--border);color:var(--text2);vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--surface2)}

  /* Badges */
  .badge{padding:3px 10px;border-radius:999px;font-size:.72rem;font-weight:600;font-family:var(--mono)}
  .badge-green{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.2)}
  .badge-red{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.2)}
  .badge-yellow{background:rgba(245,158,11,.12);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
  .badge-blue{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.2)}
  .badge-purple{background:rgba(99,102,241,.12);color:#a5b4fc;border:1px solid rgba(99,102,241,.2)}
  .badge-cyan{background:rgba(6,182,212,.12);color:#22d3ee;border:1px solid rgba(6,182,212,.2)}

  /* Messages */
  .msg{padding:10px 14px;border-radius:8px;font-size:.85rem;margin-top:12px;display:flex;align-items:center;gap:8px}
  .msg.ok{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2)}
  .msg.err{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.2)}

  /* Key display */
  .key-display{background:var(--bg);border:1px solid var(--accent);border-radius:8px;padding:12px 16px;font-family:var(--mono);font-size:.85rem;color:#60a5fa;word-break:break-all;margin-top:12px;letter-spacing:.03em;position:relative}

  /* Stats */
  .stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;position:relative;overflow:hidden}
  .stat-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(59,130,246,.05),transparent);pointer-events:none}
  .stat-num{font-size:2.2rem;font-weight:700;font-family:var(--mono);background:linear-gradient(135deg,var(--accent),var(--accent3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
  .stat-label{color:var(--text3);font-size:.8rem;margin-top:4px;font-weight:500;text-transform:uppercase;letter-spacing:.05em}

  /* Pre */
  pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:var(--mono);font-size:.8rem;color:#a5b4fc;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.6}

  /* Endpoint box */
  .endpoint-box{background:var(--bg);border:1px solid var(--border2);border-radius:8px;padding:14px;margin-top:14px;font-family:var(--mono);font-size:.78rem;color:var(--text2);line-height:2}
  .endpoint-box .method{color:#34d399;font-weight:600;margin-right:8px}
  .endpoint-box .url{color:#60a5fa}

  /* Mobile */
  @media(max-width:768px){
    .grid2,.grid3,.grid4{grid-template-columns:1fr}
    .topbar{padding:12px 16px}
    .container{padding:20px 14px}
    .card{padding:18px}
    .tabs{gap:4px}
    .tab{padding:7px 14px;font-size:.82rem}
    table{font-size:.78rem}
    th,td{padding:9px 10px}
    .stat-num{font-size:1.8rem}
  }
  @media(max-width:480px){
    .topbar-brand .ver{display:none}
    .btn{padding:8px 14px;font-size:.82rem}
  }
`;

// ─────────────────────────────────────────────
// LOGIN PAGE
// ─────────────────────────────────────────────

const loginHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aerivue — Admin Login</title>
<style>
${CSS_VARS}
${BASE_CSS}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:var(--bg)}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(59,130,246,.15),transparent);pointer-events:none}
.login-wrap{width:100%;max-width:400px;padding:20px}
.login-logo{text-align:center;margin-bottom:32px}
.login-logo .icon{font-size:2.5rem;display:block;margin-bottom:8px}
.login-logo h1{font-size:1.5rem;font-weight:700;background:linear-gradient(135deg,#60a5fa,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.login-logo p{color:var(--text3);font-size:.85rem;margin-top:4px}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:32px}
.login-btn{width:100%;margin-top:24px;padding:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:9px;font-size:1rem;cursor:pointer;font-weight:700;font-family:'Space Grotesk',sans-serif;letter-spacing:.02em;transition:all .2s}
.login-btn:hover{opacity:.9;transform:translateY(-1px);box-shadow:0 8px 24px rgba(59,130,246,.3)}
.err-box{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#f87171;font-size:.85rem;padding:10px 14px;border-radius:8px;margin-top:14px;display:none;text-align:center}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-logo">
    <span class="icon">⚡</span>
    <h1>Aerivue</h1>
    <p>API Management System</p>
  </div>
  <div class="login-card">
    <div>
      <label>Username</label>
      <input type="text" id="username" placeholder="Enter username" autocomplete="username">
      <label>Password</label>
      <input type="password" id="password" placeholder="••••••••" autocomplete="current-password">
      <button class="login-btn" onclick="doLogin()">Sign In →</button>
      <div class="err-box" id="err"></div>
    </div>
  </div>
</div>
<script>
async function doLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const errEl = document.getElementById('err');
  errEl.style.display = 'none';
  if (!username || !password) { errEl.textContent = 'Fill all fields'; errEl.style.display = 'block'; return; }
  const res = await fetch('/admin/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (res.ok) {
    window.location.href = data.role === 'superadmin' ? '/admin/dashboard' : '/admin/panel';
  } else {
    errEl.textContent = data.error || 'Login failed';
    errEl.style.display = 'block';
  }
}
document.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
</script>
</body></html>`;

// ─────────────────────────────────────────────
// SUPER ADMIN DASHBOARD
// ─────────────────────────────────────────────

const superAdminDashboardHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Super Admin — Aerivue</title>
<style>
${CSS_VARS}
${BASE_CSS}
.type-badge-number{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.2)}
.type-badge-rto{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.type-badge-image{background:rgba(168,85,247,.12);color:#c084fc;border:1px solid rgba(168,85,247,.2)}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-brand">
    <span style="font-size:1.3rem">⚡</span>
    <h1 style="background:linear-gradient(135deg,#60a5fa,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text">Aerivue</h1>
    <span class="ver">SUPER ADMIN</span>
  </div>
  <div class="topbar-actions">
    <span id="userInfo" style="font-size:.82rem;color:var(--text3)"></span>
    <button class="btn btn-ghost" onclick="logout()">Logout</button>
  </div>
</div>
<div class="container">
  <div class="tabs">
    <button class="tab active" onclick="switchTab('overview')">📊 Overview</button>
    <button class="tab" onclick="switchTab('admins')">👥 Admins</button>
    <button class="tab" onclick="switchTab('keys')">🔑 All Keys</button>
  </div>

  <!-- OVERVIEW -->
  <div class="panel active" id="panel-overview">
    <div class="grid3" style="margin-bottom:20px">
      <div class="stat-card"><div class="stat-num" id="totalAdmins">—</div><div class="stat-label">Total Admins</div></div>
      <div class="stat-card"><div class="stat-num" id="totalKeys">—</div><div class="stat-label">Total API Keys</div></div>
      <div class="stat-card"><div class="stat-num" id="activeKeys">—</div><div class="stat-label">Active Keys</div></div>
    </div>
    <div class="card">
      <div class="card-title"><span>📡</span> Available API Endpoints</div>
      <div class="endpoint-box" id="endpointList">Loading...</div>
    </div>
  </div>

  <!-- ADMINS -->
  <div class="panel" id="panel-admins">
    <div class="card">
      <div class="card-title"><span>➕</span> Create New Admin</div>
      <div class="grid2">
        <div><label>Username</label><input type="text" id="newAdminUser" placeholder="admin_name"></div>
        <div><label>Password</label><input type="password" id="newAdminPass" placeholder="••••••••"></div>
      </div>
      <div style="margin-top:16px"><button class="btn btn-primary" onclick="createAdmin()">Create Admin</button></div>
      <div id="adminMsg"></div>
    </div>
    <div class="card">
      <div class="card-title"><span>👥</span> All Admins</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Username</th><th>Created</th><th>Keys</th><th>Action</th></tr></thead>
          <tbody id="adminTable"><tr><td colspan="4" style="text-align:center;color:var(--text3);padding:24px">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ALL API KEYS -->
  <div class="panel" id="panel-keys">
    <div class="card">
      <div class="card-title"><span>🔑</span> All API Keys (across all admins)</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Key</th><th>Label</th><th>Admin</th><th>Type</th><th>Expires</th><th>Usage</th><th>Status</th><th>Action</th></tr></thead>
          <tbody id="allKeysTable"><tr><td colspan="8" style="text-align:center;color:var(--text3);padding:24px">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
const API_TYPES = ${JSON.stringify(
  API_REGISTRY.map((a) => ({ type: a.type, label: a.label, icon: a.icon, route: a.route, paramName: a.paramName }))
)};

async function apiFetch(url, opts={}) {
  const res = await fetch(url, { ...opts, headers: {'Content-Type':'application/json', ...(opts.headers||{})} });
  return [res.status, await res.json()];
}

async function logout() {
  await apiFetch('/admin/logout', {method:'POST'});
  window.location.href = '/admin';
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['overview','admins','keys'][i] === name);
  });
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  if(name==='overview') loadOverview();
  if(name==='admins') loadAdmins();
  if(name==='keys') loadAllKeys();
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = '<div class="msg '+(ok?'ok':'err')+'">'+(ok?'✓':'✗')+' '+text+'</div>';
  setTimeout(() => el.innerHTML='', 4000);
}

function getTypeBadge(type) {
  const api = API_TYPES.find(a => a.type === type);
  const cls = 'type-badge-'+type;
  return '<span class="badge '+cls+'">'+(api ? api.icon+' '+api.label : type)+'</span>';
}

async function loadOverview() {
  const [,stats] = await apiFetch('/admin/api/stats');
  document.getElementById('totalAdmins').textContent = stats.totalAdmins ?? '—';
  document.getElementById('totalKeys').textContent = stats.totalKeys ?? '—';
  document.getElementById('activeKeys').textContent = stats.activeKeys ?? '—';

  const ep = document.getElementById('endpointList');
  ep.innerHTML = API_TYPES.map(a =>
    '<div><span class="method">GET</span><span class="url">/'+a.route.replace('/','')+'?'+a.paramName+'=VALUE&apikey=YOUR_KEY</span></div>'
  ).join('');
}

async function loadAdmins() {
  const [,data] = await apiFetch('/admin/api/admins');
  const tb = document.getElementById('adminTable');
  if(!data.admins?.length){
    tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:20px">No admins yet</td></tr>';return;
  }
  tb.innerHTML = data.admins.map(a => \`<tr>
    <td><strong style="color:var(--text)">\${a.username}</strong></td>
    <td>\${new Date(a.createdAt).toLocaleDateString()}</td>
    <td><span class="badge badge-blue">\${a.keyCount} keys</span></td>
    <td><button class="btn btn-danger" onclick="deleteAdmin('\${a.username}')">Delete</button></td>
  </tr>\`).join('');
}

async function createAdmin() {
  const username = document.getElementById('newAdminUser').value.trim();
  const password = document.getElementById('newAdminPass').value;
  if(!username||!password) return showMsg('adminMsg','Fill all fields',false);
  const [status,data] = await apiFetch('/admin/api/admins', {method:'POST', body:JSON.stringify({username,password})});
  showMsg('adminMsg', data.message||data.error, status===201);
  if(status===201) {
    document.getElementById('newAdminUser').value='';
    document.getElementById('newAdminPass').value='';
    loadAdmins(); loadOverview();
  }
}

async function deleteAdmin(username) {
  if(!confirm('Delete admin "'+username+'" and ALL their API keys?')) return;
  const [status,data] = await apiFetch('/admin/api/admins/'+username, {method:'DELETE'});
  showMsg('adminMsg', data.message||data.error, status===200);
  loadAdmins(); loadOverview();
}

async function loadAllKeys() {
  const [,data] = await apiFetch('/admin/api/all-keys');
  const tb = document.getElementById('allKeysTable');
  if(!data.keys?.length){
    tb.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--text3);padding:20px">No keys yet</td></tr>';return;
  }
  tb.innerHTML = data.keys.map(k => {
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    const statusBadge = (!k.isActive||expired)
      ? '<span class="badge badge-red">'+(expired?'Expired':'Disabled')+'</span>'
      : '<span class="badge badge-green">Active</span>';
    const usage = k.usageLimit ? k.usageCount+'/'+k.usageLimit : k.usageCount+'/∞';
    return \`<tr>
      <td style="font-family:var(--mono);font-size:.72rem;color:#60a5fa">\${k.key}</td>
      <td>\${k.label||'—'}</td>
      <td style="color:var(--text)">\${k.createdBy}</td>
      <td>\${getTypeBadge(k.keyType)}</td>
      <td style="font-size:.8rem">\${exp.toLocaleDateString()}</td>
      <td style="font-family:var(--mono);font-size:.8rem">\${usage}</td>
      <td>\${statusBadge}</td>
      <td><button class="btn btn-danger" onclick="superDeleteKey('\${k._id}')">Delete</button></td>
    </tr>\`;
  }).join('');
}

async function superDeleteKey(id) {
  if(!confirm('Delete this API key?')) return;
  const [status,data] = await apiFetch('/admin/api/all-keys/'+id, {method:'DELETE'});
  showMsg('adminMsg', data.message||data.error, status===200);
  loadAllKeys(); loadOverview();
}

apiFetch('/admin/api/me').then(([,d]) => {
  document.getElementById('userInfo').textContent = d.username || '';
});
loadOverview();
</script>
</body></html>`;

// ─────────────────────────────────────────────
// ADMIN PANEL
// ─────────────────────────────────────────────

const adminPanelHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel — Aerivue</title>
<style>
${CSS_VARS}
${BASE_CSS}
.type-badge-number{background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.2)}
.type-badge-rto{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.type-badge-image{background:rgba(168,85,247,.12);color:#c084fc;border:1px solid rgba(168,85,247,.2)}
.tabs .tab.active{background:var(--green);border-color:var(--green)}
.generate-area{display:none;margin-top:16px;padding:16px;background:var(--bg);border:1px solid var(--border);border-radius:8px}
.gen-result img{max-width:100%;border-radius:8px;margin-top:12px;border:1px solid var(--border)}
.spinner{display:inline-block;width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-brand">
    <span style="font-size:1.3rem">⚡</span>
    <h1 style="color:var(--green)">Aerivue</h1>
    <span class="ver">ADMIN</span>
  </div>
  <div class="topbar-actions">
    <span id="welcomeUser" style="font-size:.82rem;color:var(--text3)"></span>
    <button class="btn btn-ghost" onclick="logout()">Logout</button>
  </div>
</div>
<div class="container">
  <div class="tabs">
    <button class="tab active" onclick="switchTab('keys')">🔑 My Keys</button>
    <button class="tab" onclick="switchTab('test')">🧪 Test APIs</button>
  </div>

  <!-- MY KEYS -->
  <div class="panel active" id="panel-keys">
    <!-- Create Key -->
    <div class="card">
      <div class="card-title"><span>➕</span> Generate New API Key</div>
      <div class="grid2" style="margin-bottom:4px">
        <div>
          <label>API Type</label>
          <select id="keyType">
            ${API_REGISTRY.map(
              (a) =>
                `<option value="${a.type}">${a.icon} ${a.label}</option>`
            ).join("")}
          </select>
        </div>
        <div>
          <label>Label (optional)</label>
          <input type="text" id="keyLabel" placeholder="e.g. My App">
        </div>
        <div>
          <label>Expires In</label>
          <select id="keyExpiry">
            <option value="1">1 Day</option>
            <option value="7" selected>7 Days</option>
            <option value="30">30 Days</option>
            <option value="90">90 Days</option>
            <option value="365">1 Year</option>
          </select>
        </div>
        <div>
          <label>Usage Limit (0 = unlimited)</label>
          <input type="number" id="keyLimit" value="0" min="0">
        </div>
      </div>
      <div style="margin-top:16px">
        <button class="btn btn-green" onclick="createKey()">⚡ Generate Key</button>
      </div>
      <div id="newKeyDisplay" style="display:none">
        <label>Your New API Key — Copy it now!</label>
        <div class="key-display" id="newKeyVal"></div>
        <button class="btn-copy" style="margin-top:8px" onclick="copyText(document.getElementById('newKeyVal').textContent)">Copy Key</button>
      </div>
      <div id="keyMsg"></div>
    </div>

    <!-- Keys Table -->
    <div class="card">
      <div class="card-title"><span>🔑</span> My API Keys</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Key</th><th>Label</th><th>Type</th><th>Expires</th><th>Usage</th><th>Status</th><th>Action</th></tr></thead>
          <tbody id="myKeysTable"><tr><td colspan="7" style="text-align:center;color:var(--text3);padding:24px">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- Endpoints Reference -->
    <div class="card">
      <div class="card-title"><span>📡</span> API Endpoints Reference</div>
      <div id="endpointRef"></div>
    </div>
  </div>

  <!-- TEST APIs -->
  <div class="panel" id="panel-test">
    <!-- Number Lookup -->
    <div class="card">
      <div class="card-title"><span>📞</span> Test Number Lookup</div>
      <div class="grid2">
        <div><label>Phone Number</label><input type="text" id="testNumber" placeholder="9876543210"></div>
        <div><label>API Key (ak_...)</label><input type="text" id="testNumberKey" placeholder="ak_..."></div>
      </div>
      <div style="margin-top:14px"><button class="btn btn-primary" onclick="testLookup()">Lookup</button></div>
      <pre id="lookupResult" style="display:none;margin-top:14px"></pre>
    </div>

    <!-- RTO Lookup -->
    <div class="card">
      <div class="card-title"><span>🚗</span> Test RTO Lookup</div>
      <div class="grid2">
        <div><label>Vehicle RC Number</label><input type="text" id="testRC" placeholder="KL43G1669"></div>
        <div><label>API Key (rto_...)</label><input type="text" id="testRTOKey" placeholder="rto_..."></div>
      </div>
      <div style="margin-top:14px"><button class="btn btn-primary" onclick="testRTO()">Lookup</button></div>
      <pre id="rtoResult" style="display:none;margin-top:14px"></pre>
    </div>

    <!-- Image Generator -->
    <div class="card">
      <div class="card-title"><span>🎨</span> Test Image / Logo Generator</div>
      <div class="grid2">
        <div><label>Prompt</label><input type="text" id="testPrompt" placeholder="e.g. a futuristic lion logo"></div>
        <div><label>API Key (img_...)</label><input type="text" id="testImgKey" placeholder="img_..."></div>
      </div>
      <div style="margin-top:14px"><button class="btn btn-primary" id="genBtn" onclick="testGenerate()">Generate</button></div>
      <div id="genResult" style="margin-top:14px"></div>
    </div>
  </div>
</div>

<script>
const API_TYPES = ${JSON.stringify(
  API_REGISTRY.map((a) => ({
    type: a.type,
    label: a.label,
    icon: a.icon,
    route: a.route,
    paramName: a.paramName,
    prefix: a.prefix,
  }))
)};

async function apiFetch(url, opts={}) {
  const res = await fetch(url, { ...opts, headers: {'Content-Type':'application/json', ...(opts.headers||{})} });
  return [res.status, await res.json()];
}

async function logout() {
  await apiFetch('/admin/logout', {method:'POST'});
  window.location.href = '/admin';
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['keys','test'][i] === name);
  });
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = '<div class="msg '+(ok?'ok':'err')+'">'+(ok?'✓':'✗')+' '+text+'</div>';
  setTimeout(() => el.innerHTML='', 5000);
}

function getTypeBadge(type) {
  const api = API_TYPES.find(a => a.type === type);
  return '<span class="badge type-badge-'+type+'">'+(api ? api.icon+' '+api.label : type)+'</span>';
}

function copyText(t) {
  navigator.clipboard.writeText(t);
}

async function loadMyKeys() {
  const [,data] = await apiFetch('/admin/api/my-keys');
  const tb = document.getElementById('myKeysTable');
  if(!data.keys?.length){
    tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px">No keys created yet</td></tr>';
    return;
  }
  tb.innerHTML = data.keys.map(k => {
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    let statusBadge;
    if(!k.isActive) statusBadge='<span class="badge badge-red">Disabled</span>';
    else if(expired) statusBadge='<span class="badge badge-yellow">Expired</span>';
    else statusBadge='<span class="badge badge-green">Active</span>';
    const usage = k.usageLimit ? k.usageCount+'/'+k.usageLimit : k.usageCount+'/∞';
    return \`<tr>
      <td style="font-family:var(--mono);font-size:.72rem;color:#60a5fa">
        \${k.key.substring(0,16)}...
        <button class="btn-copy" onclick="copyText('\${k.key}')">Copy</button>
      </td>
      <td>\${k.label||'—'}</td>
      <td>\${getTypeBadge(k.keyType)}</td>
      <td style="font-size:.8rem">\${exp.toLocaleDateString()}</td>
      <td style="font-family:var(--mono);font-size:.8rem">\${usage}</td>
      <td>\${statusBadge}</td>
      <td><button class="btn btn-danger" onclick="deleteKey('\${k._id}')">Delete</button></td>
    </tr>\`;
  }).join('');
}

async function createKey() {
  const keyType = document.getElementById('keyType').value;
  const label = document.getElementById('keyLabel').value.trim();
  const days = parseInt(document.getElementById('keyExpiry').value);
  const usageLimit = parseInt(document.getElementById('keyLimit').value) || 0;
  const [status,data] = await apiFetch('/admin/api/my-keys', {
    method:'POST',
    body: JSON.stringify({ label, days, usageLimit, keyType })
  });
  if(status===201) {
    document.getElementById('newKeyVal').textContent = data.key;
    document.getElementById('newKeyDisplay').style.display='block';
    document.getElementById('keyLabel').value='';
    loadMyKeys();
  } else {
    showMsg('keyMsg', data.error||'Failed to create key', false);
  }
}

async function deleteKey(id) {
  if(!confirm('Delete this API key? This cannot be undone.')) return;
  const [status,data] = await apiFetch('/admin/api/my-keys/'+id, {method:'DELETE'});
  showMsg('keyMsg', data.message||data.error, status===200);
  loadMyKeys();
}

async function testLookup() {
  const number = document.getElementById('testNumber').value.trim();
  const key = document.getElementById('testNumberKey').value.trim();
  if(!number||!key){alert('Enter number and API key');return;}
  const res = await fetch('/lookup?number='+encodeURIComponent(number)+'&apikey='+encodeURIComponent(key));
  const data = await res.json();
  const el = document.getElementById('lookupResult');
  el.style.display='block';
  el.textContent = JSON.stringify(data, null, 2);
}

async function testRTO() {
  const rc = document.getElementById('testRC').value.trim();
  const key = document.getElementById('testRTOKey').value.trim();
  if(!rc||!key){alert('Enter RC number and API key');return;}
  const res = await fetch('/rto?rc='+encodeURIComponent(rc)+'&apikey='+encodeURIComponent(key));
  const data = await res.json();
  const el = document.getElementById('rtoResult');
  el.style.display='block';
  el.textContent = JSON.stringify(data, null, 2);
}

async function testGenerate() {
  const prompt = document.getElementById('testPrompt').value.trim();
  const key = document.getElementById('testImgKey').value.trim();
  if(!prompt||!key){alert('Enter prompt and API key');return;}
  const genBtn = document.getElementById('genBtn');
  const genResult = document.getElementById('genResult');
  genBtn.disabled=true;
  genBtn.innerHTML='<span class="spinner"></span> Generating...';
  genResult.innerHTML='<div style="color:var(--text2);font-size:.85rem">⏳ Starting generation...</div>';
  try {
    const res = await fetch('/generate?prompt='+encodeURIComponent(prompt)+'&apikey='+encodeURIComponent(key));
    const data = await res.json();
    if(!res.ok){ genResult.innerHTML='<pre>'+JSON.stringify(data,null,2)+'</pre>'; return; }
    const taskId = data.task_id;
    genResult.innerHTML='<div style="color:var(--text2);font-size:.85rem">⏳ Task started: <code style="color:#60a5fa">'+taskId+'</code><br>Polling for result...</div>';
    let attempts=0;
    const poll = setInterval(async () => {
      attempts++;
      const cr = await fetch('/generate/check?task_id='+encodeURIComponent(taskId)+'&apikey='+encodeURIComponent(key));
      const cd = await cr.json();
      if(cd.image_url){
        clearInterval(poll);
        genResult.innerHTML='<div style="color:#34d399;font-size:.85rem;margin-bottom:8px">✓ Image ready!</div><img src="'+cd.image_url+'" style="max-width:100%;border-radius:8px;border:1px solid var(--border)"><div style="margin-top:8px"><a href="'+cd.image_url+'" target="_blank" class="btn btn-primary" style="font-size:.8rem;padding:6px 14px">Open Full Image</a></div>';
        genBtn.disabled=false; genBtn.textContent='Generate';
      } else if(attempts>30){
        clearInterval(poll);
        genResult.innerHTML='<div style="color:var(--yellow)">⚠ Timed out. Try again.</div>';
        genBtn.disabled=false; genBtn.textContent='Generate';
      }
    }, 3000);
  } catch(e) {
    genResult.innerHTML='<div style="color:var(--red)">Error: '+e.message+'</div>';
    genBtn.disabled=false; genBtn.textContent='Generate';
  }
}

// Build endpoint reference
const epRef = document.getElementById('endpointRef');
if(epRef) {
  epRef.innerHTML = API_TYPES.map(a => \`
    <div style="margin-bottom:16px;padding:14px;background:var(--bg);border:1px solid var(--border);border-radius:8px">
      <div style="margin-bottom:8px;font-weight:600;color:var(--text)">\${a.icon} \${a.label}</div>
      <div style="font-family:var(--mono);font-size:.78rem;color:#60a5fa">GET \${a.route}?\${a.paramName}=VALUE&apikey=YOUR_KEY</div>
      <div style="font-size:.78rem;color:var(--text3);margin-top:4px">Key prefix: <code style="color:#a5b4fc">\${a.prefix}...</code></div>
    </div>
  \`).join('');
}

apiFetch('/admin/api/me').then(([,d]) => {
  document.getElementById('welcomeUser').textContent = d.username || '';
});
loadMyKeys();
</script>
</body></html>`;

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────

app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      return res.redirect(
        isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel"
      );
    } catch {}
  }
  res.send(loginHtml());
});

app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => {
  res.send(superAdminDashboardHtml());
});

app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.send(adminPanelHtml());
});

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing credentials" });

  if (username === process.env.SUPER_ADMIN_USERNAME) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const token = signToken({ username, role: "superadmin" });
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const token = signToken({ username, role: "admin" });
  res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ─────────────────────────────────────────────
// SUPER ADMIN API ROUTES
// ─────────────────────────────────────────────

app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  const totalAdmins = await Admin.countDocuments();
  const totalKeys = await ApiKey.countDocuments();
  const activeKeys = await ApiKey.countDocuments({
    isActive: true,
    expiresAt: { $gt: new Date() },
  });
  res.json({ totalAdmins, totalKeys, activeKeys });
});

app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const admins = await Admin.find({}, { password: 0 }).lean();
  const result = await Promise.all(
    admins.map(async (a) => ({
      ...a,
      keyCount: await ApiKey.countDocuments({ createdBy: a.username }),
    }))
  );
  res.json({ admins: result });
});

app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });
  if (username === process.env.SUPER_ADMIN_USERNAME)
    return res.status(400).json({ error: "Reserved username" });
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(409).json({ error: "Admin already exists" });
  const hashed = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hashed });
  res.status(201).json({ message: `Admin "${username}" created successfully` });
});

app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (username === process.env.SUPER_ADMIN_USERNAME)
    return res.status(400).json({ error: "Cannot delete super admin" });
  const admin = await Admin.findOneAndDelete({ username });
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  await ApiKey.deleteMany({ createdBy: username });
  res.json({ message: `Admin "${username}" and all their keys deleted` });
});

app.get("/admin/api/all-keys", authMiddleware, superAdminOnly, async (req, res) => {
  const keys = await ApiKey.find().sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.delete("/admin/api/all-keys/:id", authMiddleware, superAdminOnly, async (req, res) => {
  const key = await ApiKey.findByIdAndDelete(req.params.id);
  if (!key) return res.status(404).json({ error: "Key not found" });
  res.json({ message: "Key deleted" });
});

// ─────────────────────────────────────────────
// ADMIN KEY ROUTES
// ─────────────────────────────────────────────

app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = await ApiKey.find({ createdBy: req.user.username })
    .sort({ createdAt: -1 })
    .lean();
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find((a) => a.type === keyType))
    return res.status(400).json({ error: "Invalid key type" });
  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000);
  const key = generateApiKey(keyType);
  await ApiKey.create({
    key,
    label: label || "",
    createdBy: req.user.username,
    expiresAt,
    usageLimit: usageLimit > 0 ? usageLimit : null,
    keyType,
  });
  res.status(201).json({ key, expiresAt, message: "API key created" });
});

app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const filter = { _id: req.params.id };
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const key = await ApiKey.findOneAndDelete(filter);
  if (!key) return res.status(404).json({ error: "Key not found or unauthorized" });
  res.json({ message: "Key deleted" });
});

// ─────────────────────────────────────────────
// PUBLIC API ROUTES
// ─────────────────────────────────────────────

// 1. Number Lookup → /lookup?number=XXXX
app.get("/lookup", async (req, res) => {
  const { number } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!number) return res.status(400).json({ error: "number query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });

  const { error, status, keyDoc } = await validateApiKey(apiKey, "number");
  if (error) return res.status(status).json({ error });

  try {
    const upstreamUrl = `${process.env.UPSTREAM_API_URL}?number=${encodeURIComponent(number)}`;
    const response = await axios.get(upstreamUrl, { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.owner = "@aerivue";
    if (data.result && typeof data.result === "object") data.result.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream API error" });
  }
});

// 2. RTO Lookup → /rto?rc=XXXX
app.get("/rto", async (req, res) => {
  const { rc } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!rc) return res.status(400).json({ error: "rc query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });

  const { error, status, keyDoc } = await validateApiKey(apiKey, "rto");
  if (error) return res.status(status).json({ error });

  try {
    const upstreamUrl = `${process.env.UPSTREAM_RTO_API_URL}?rc=${encodeURIComponent(rc)}`;
    const response = await axios.get(upstreamUrl, { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream RTO API error" });
  }
});

// 3. Image Generation (async two-step) → /generate?prompt=XXXX
app.get("/generate", async (req, res) => {
  const { prompt } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!prompt) return res.status(400).json({ error: "prompt query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });

  const { error, status, keyDoc } = await validateApiKey(apiKey, "image");
  if (error) return res.status(status).json({ error });

  try {
    const upstreamUrl = `${process.env.UPSTREAM_IMAGE_API_URL}?prompt=${encodeURIComponent(prompt)}`;
    const response = await axios.get(upstreamUrl, { timeout: 15000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.credit = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream image API error" });
  }
});

// 3b. Image Check → /generate/check?task_id=XXXX
app.get("/generate/check", async (req, res) => {
  const { task_id } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!task_id) return res.status(400).json({ error: "task_id required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });

  // Validate key exists (no usage increment for check)
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return res.status(401).json({ error: "Invalid API key" });
  if (!keyDoc.isActive) return res.status(403).json({ error: "API key is disabled" });
  if (keyDoc.keyType !== "image") return res.status(403).json({ error: "Not authorized" });
  if (keyDoc.expiresAt < new Date()) return res.status(403).json({ error: "API key expired" });

  try {
    const checkUrl = `${process.env.UPSTREAM_IMAGE_CHECK_URL}?task=${encodeURIComponent(task_id)}`;
    const response = await axios.get(checkUrl, { timeout: 10000 });
    const data = response.data;
    data.credit = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream check API error" });
  }
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────

async function start() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("✅ MongoDB connected");
    app.listen(process.env.PORT || 3000, () => {
      console.log(`\n🚀 Server: http://localhost:${process.env.PORT || 3000}`);
      console.log(`🔐 Admin:  http://localhost:${process.env.PORT || 3000}/admin`);
      console.log(`\n📡 Public Endpoints:`);
      API_REGISTRY.forEach((a) => {
        console.log(`   ${a.icon}  /${a.route.replace("/", "")}?${a.paramName}=VALUE&apikey=YOUR_KEY`);
      });
      console.log("");
    });
  } catch (err) {
    console.error("❌ Startup error:", err.message);
    process.exit(1);
  }
}

start();
