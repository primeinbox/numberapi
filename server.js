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
// MONGODB SCHEMAS
// ─────────────────────────────────────────────

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, default: "superadmin" },
});

const ApiKeySchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  label: { type: String, default: "" },
  createdBy: { type: String, required: true }, // admin username
  expiresAt: { type: Date, required: true },
  usageCount: { type: Number, default: 0 },
  usageLimit: { type: Number, default: null }, // null = unlimited
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: null },
});

const Admin = mongoose.model("Admin", AdminSchema);
const ApiKey = mongoose.model("ApiKey", ApiKeySchema);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function generateApiKey() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = "ak_";
  for (let i = 0; i < 32; i++) key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

// Middleware: verify JWT from cookie or Authorization header
function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Middleware: only super admin
function superAdminOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username)) {
    return res.status(403).json({ error: "Super admin access required" });
  }
  next();
}

// ─────────────────────────────────────────────
// SUPER ADMIN HTML PANEL
// ─────────────────────────────────────────────

const superAdminLoginHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Super Admin Login</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{min-height:100vh;background:#0f172a;display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',sans-serif}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;width:360px}
  h2{color:#f1f5f9;text-align:center;margin-bottom:8px;font-size:1.5rem}
  .badge{text-align:center;color:#94a3b8;font-size:.8rem;margin-bottom:28px}
  label{display:block;color:#cbd5e1;font-size:.85rem;margin-bottom:6px;margin-top:16px}
  input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #475569;border-radius:8px;color:#f1f5f9;font-size:.95rem}
  input:focus{outline:none;border-color:#6366f1}
  button{width:100%;margin-top:24px;padding:12px;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer;font-weight:600}
  button:hover{background:#4f46e5}
  .error{color:#f87171;font-size:.85rem;margin-top:12px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h2>🔐 Super Admin</h2>
  <div class="badge">API Management System</div>
  <form id="loginForm">
    <label>Username</label>
    <input type="text" id="username" placeholder="superadmin" required>
    <label>Password</label>
    <input type="password" id="password" placeholder="••••••••" required>
    <button type="submit">Login</button>
    <div class="error" id="err"></div>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const res = await fetch('/admin/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      username: document.getElementById('username').value,
      password: document.getElementById('password').value
    })
  });
  const data = await res.json();
  if (res.ok) {
  if (data.role === "superadmin") {
    window.location.href = "/admin/dashboard";
  } else {
    window.location.href = "/admin/panel";
  }
}
  else document.getElementById('err').textContent = data.error || 'Login failed';
});
</script>
</body></html>`;

const superAdminDashboardHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Super Admin Dashboard</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0f172a;font-family:'Segoe UI',sans-serif;color:#e2e8f0;min-height:100vh}
  .topbar{background:#1e293b;border-bottom:1px solid #334155;padding:14px 28px;display:flex;justify-content:space-between;align-items:center}
  .topbar h1{font-size:1.1rem;color:#a5b4fc}
  .topbar span{font-size:.85rem;color:#94a3b8}
  .logout{background:transparent;border:1px solid #475569;color:#94a3b8;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:.85rem}
  .logout:hover{border-color:#f87171;color:#f87171}
  .container{max-width:1100px;margin:32px auto;padding:0 20px}
  .tabs{display:flex;gap:8px;margin-bottom:24px}
  .tab{padding:8px 20px;border-radius:8px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font-size:.9rem}
  .tab.active{background:#6366f1;border-color:#6366f1;color:#fff}
  .panel{display:none}.panel.active{display:block}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
  h3{color:#f1f5f9;margin-bottom:16px;font-size:1rem}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  label{display:block;color:#cbd5e1;font-size:.82rem;margin-bottom:5px;margin-top:12px}
  input{width:100%;padding:9px 12px;background:#0f172a;border:1px solid #475569;border-radius:7px;color:#f1f5f9;font-size:.9rem}
  input:focus{outline:none;border-color:#6366f1}
  .btn{padding:9px 20px;border:none;border-radius:7px;cursor:pointer;font-size:.88rem;font-weight:600}
  .btn-primary{background:#6366f1;color:#fff}.btn-primary:hover{background:#4f46e5}
  .btn-danger{background:#ef4444;color:#fff;font-size:.8rem;padding:5px 12px}.btn-danger:hover{background:#dc2626}
  .btn-sm{font-size:.8rem;padding:5px 12px}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:10px 12px;color:#94a3b8;border-bottom:1px solid #334155;font-weight:500}
  td{padding:10px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1}
  tr:hover td{background:#1e293b}
  .badge-green{background:#052e16;color:#4ade80;padding:2px 10px;border-radius:999px;font-size:.75rem}
  .badge-red{background:#2d0a0a;color:#f87171;padding:2px 10px;border-radius:999px;font-size:.75rem}
  .msg{padding:10px 14px;border-radius:7px;font-size:.85rem;margin-top:12px}
  .msg.ok{background:#052e16;color:#4ade80}.msg.err{background:#2d0a0a;color:#f87171}
  .stat{text-align:center;padding:20px}
  .stat-num{font-size:2rem;font-weight:700;color:#a5b4fc}
  .stat-label{color:#94a3b8;font-size:.85rem;margin-top:4px}
  @media(max-width:600px){.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="topbar">
  <h1>🛡️ Super Admin Dashboard</h1>
  <div style="display:flex;align-items:center;gap:12px">
    <span id="userInfo"></span>
    <button class="logout" onclick="logout()">Logout</button>
  </div>
</div>
<div class="container">
  <div class="tabs">
    <button class="tab active" onclick="switchTab('overview')">Overview</button>
    <button class="tab" onclick="switchTab('admins')">Manage Admins</button>
    <button class="tab" onclick="switchTab('keys')">All API Keys</button>
  </div>

  <!-- OVERVIEW -->
  <div class="panel active" id="panel-overview">
    <div class="card" style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">
      <div class="stat"><div class="stat-num" id="totalAdmins">-</div><div class="stat-label">Total Admins</div></div>
      <div class="stat"><div class="stat-num" id="totalKeys">-</div><div class="stat-label">Total API Keys</div></div>
      <div class="stat"><div class="stat-num" id="activeKeys">-</div><div class="stat-label">Active Keys</div></div>
    </div>
  </div>

  <!-- ADMINS -->
  <div class="panel" id="panel-admins">
    <div class="card">
      <h3>➕ Create New Admin</h3>
      <div class="grid2">
        <div>
          <label>Username</label>
          <input type="text" id="newAdminUser" placeholder="admin_username">
        </div>
        <div>
          <label>Password</label>
          <input type="password" id="newAdminPass" placeholder="••••••••">
        </div>
      </div>
      <div style="margin-top:16px">
        <button class="btn btn-primary" onclick="createAdmin()">Create Admin</button>
      </div>
      <div id="adminMsg"></div>
    </div>
    <div class="card">
      <h3>👥 All Admins</h3>
      <table>
        <thead><tr><th>Username</th><th>Created</th><th>API Keys</th><th>Action</th></tr></thead>
        <tbody id="adminTable"><tr><td colspan="4" style="text-align:center;color:#475569">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- ALL API KEYS -->
  <div class="panel" id="panel-keys">
    <div class="card">
      <h3>🔑 All API Keys (across all admins)</h3>
      <table>
        <thead><tr><th>Key</th><th>Label</th><th>Admin</th><th>Expires</th><th>Usage</th><th>Status</th><th>Action</th></tr></thead>
        <tbody id="allKeysTable"><tr><td colspan="7" style="text-align:center;color:#475569">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<script>
async function apiFetch(url, opts={}) {
  const res = await fetch(url, { ...opts, headers: {'Content-Type':'application/json', ...(opts.headers||{})} });
  return [res.status, await res.json()];
}

async function logout() {
  await apiFetch('/admin/logout', {method:'POST'});
  window.location.href = '/admin';
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i)=> t.classList.toggle('active', ['overview','admins','keys'][i]===name));
  document.querySelectorAll('.panel').forEach(p=> p.classList.remove('active'));
  document.getElementById('panel-'+name).classList.add('active');
  if(name==='overview') loadOverview();
  if(name==='admins') loadAdmins();
  if(name==='keys') loadAllKeys();
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = '<div class="msg '+(ok?'ok':'err')+'">'+text+'</div>';
  setTimeout(()=>el.innerHTML='', 4000);
}

async function loadOverview() {
  const [,stats] = await apiFetch('/admin/api/stats');
  document.getElementById('totalAdmins').textContent = stats.totalAdmins ?? '-';
  document.getElementById('totalKeys').textContent = stats.totalKeys ?? '-';
  document.getElementById('activeKeys').textContent = stats.activeKeys ?? '-';
}

async function loadAdmins() {
  const [,data] = await apiFetch('/admin/api/admins');
  const tb = document.getElementById('adminTable');
  if(!data.admins?.length){tb.innerHTML='<tr><td colspan="4" style="text-align:center;color:#475569">No admins yet</td></tr>';return;}
  tb.innerHTML = data.admins.map(a=>\`<tr>
    <td><strong>\${a.username}</strong></td>
    <td>\${new Date(a.createdAt).toLocaleDateString()}</td>
    <td>\${a.keyCount}</td>
    <td><button class="btn btn-danger" onclick="deleteAdmin('\${a.username}')">Delete</button></td>
  </tr>\`).join('');
}

async function createAdmin() {
  const username = document.getElementById('newAdminUser').value.trim();
  const password = document.getElementById('newAdminPass').value;
  if(!username||!password) return showMsg('adminMsg','Fill all fields',false);
  const [status,data] = await apiFetch('/admin/api/admins', {method:'POST', body:JSON.stringify({username,password})});
  showMsg('adminMsg', data.message||data.error, status===200||status===201);
  if(status===201) { document.getElementById('newAdminUser').value=''; document.getElementById('newAdminPass').value=''; loadAdmins(); loadOverview(); }
}

async function deleteAdmin(username) {
  if(!confirm('Delete admin "'+username+'" and all their API keys?')) return;
  const [status,data] = await apiFetch('/admin/api/admins/'+username, {method:'DELETE'});
  showMsg('adminMsg', data.message||data.error, status===200);
  loadAdmins(); loadOverview();
}

async function loadAllKeys() {
  const [,data] = await apiFetch('/admin/api/all-keys');
  const tb = document.getElementById('allKeysTable');
  if(!data.keys?.length){tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:#475569">No keys yet</td></tr>';return;}
  tb.innerHTML = data.keys.map(k=>{
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    const status = (!k.isActive||expired) ? '<span class="badge-red">Inactive</span>' : '<span class="badge-green">Active</span>';
    const usage = k.usageLimit ? k.usageCount+'/'+k.usageLimit : k.usageCount+'/∞';
    return \`<tr>
      <td style="font-family:monospace;font-size:.78rem">\${k.key}</td>
      <td>\${k.label||'-'}</td>
      <td>\${k.createdBy}</td>
      <td>\${exp.toLocaleDateString()}</td>
      <td>\${usage}</td>
      <td>\${status}</td>
      <td><button class="btn btn-danger btn-sm" onclick="superDeleteKey('\${k._id}')">Delete</button></td>
    </tr>\`;
  }).join('');
}

async function superDeleteKey(id) {
  if(!confirm('Delete this API key?')) return;
  const [status,data] = await apiFetch('/admin/api/all-keys/'+id, {method:'DELETE'});
  alert(data.message||data.error);
  loadAllKeys(); loadOverview();
}

loadOverview();
</script>
</body></html>`;

const adminPanelHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Panel</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#0f172a;font-family:'Segoe UI',sans-serif;color:#e2e8f0;min-height:100vh}
  .topbar{background:#1e293b;border-bottom:1px solid #334155;padding:14px 28px;display:flex;justify-content:space-between;align-items:center}
  .topbar h1{font-size:1.1rem;color:#34d399}
  .logout{background:transparent;border:1px solid #475569;color:#94a3b8;padding:6px 16px;border-radius:6px;cursor:pointer;font-size:.85rem}
  .logout:hover{border-color:#f87171;color:#f87171}
  .container{max-width:1000px;margin:32px auto;padding:0 20px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
  h3{color:#f1f5f9;margin-bottom:16px;font-size:1rem}
  label{display:block;color:#cbd5e1;font-size:.82rem;margin-bottom:5px;margin-top:12px}
  input,select{width:100%;padding:9px 12px;background:#0f172a;border:1px solid #475569;border-radius:7px;color:#f1f5f9;font-size:.9rem}
  input:focus,select:focus{outline:none;border-color:#34d399}
  .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .btn{padding:9px 20px;border:none;border-radius:7px;cursor:pointer;font-size:.88rem;font-weight:600}
  .btn-primary{background:#10b981;color:#fff}.btn-primary:hover{background:#059669}
  .btn-danger{background:#ef4444;color:#fff;font-size:.8rem;padding:5px 12px}.btn-danger:hover{background:#dc2626}
  .btn-copy{background:#334155;color:#94a3b8;font-size:.78rem;padding:4px 10px;border:none;border-radius:5px;cursor:pointer}
  .btn-copy:hover{background:#475569;color:#fff}
  table{width:100%;border-collapse:collapse;font-size:.83rem}
  th{text-align:left;padding:10px 12px;color:#94a3b8;border-bottom:1px solid #334155;font-weight:500}
  td{padding:10px 12px;border-bottom:1px solid #0f172a;color:#cbd5e1}
  tr:hover td{background:#0f172a}
  .badge-green{background:#052e16;color:#4ade80;padding:2px 10px;border-radius:999px;font-size:.75rem}
  .badge-red{background:#2d0a0a;color:#f87171;padding:2px 10px;border-radius:999px;font-size:.75rem}
  .badge-yellow{background:#1c1100;color:#fbbf24;padding:2px 10px;border-radius:999px;font-size:.75rem}
  .msg{padding:10px 14px;border-radius:7px;font-size:.85rem;margin-top:12px}
  .msg.ok{background:#052e16;color:#4ade80}.msg.err{background:#2d0a0a;color:#f87171}
  .key-display{background:#0f172a;border:1px solid #334155;border-radius:7px;padding:10px 14px;font-family:monospace;font-size:.85rem;color:#a5b4fc;word-break:break-all;margin-top:12px}
  @media(max-width:650px){.grid3,.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="topbar">
  <h1>🗝️ Admin Panel — <span id="welcomeUser"></span></h1>
  <button class="logout" onclick="logout()">Logout</button>
</div>
<div class="container">
  <!-- Create API Key -->
  <div class="card">
    <h3>➕ Create New API Key</h3>
    <div class="grid3">
      <div>
        <label>Label (optional)</label>
        <input type="text" id="keyLabel" placeholder="e.g. My App Key">
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
        <input type="number" id="keyLimit" placeholder="0" value="0" min="0">
      </div>
    </div>
    <div style="margin-top:16px">
      <button class="btn btn-primary" onclick="createKey()">Generate API Key</button>
    </div>
    <div id="newKeyDisplay" style="display:none">
      <label style="margin-top:16px">Your New API Key (copy it now):</label>
      <div class="key-display" id="newKeyVal"></div>
    </div>
    <div id="keyMsg"></div>
  </div>

  <!-- My Keys -->
  <div class="card">
  <h3>🔑 My API Keys</h3>

  <table>
    <thead>
      <tr>
        <th>Key</th>
        <th>Label</th>
        <th>Expires</th>
        <th>Usage</th>
        <th>Status</th>
        <th>Action</th>
      </tr>
    </thead>

    <tbody id="myKeysTable">
      <tr>
        <td colspan="6" style="text-align:center;color:#475569">
          Loading...
        </td>
      </tr>
    </tbody>
  </table>

  <div style="margin-top:14px;font-size:.9rem;color:#94a3b8">
    <b>Endpoint Example:</b><br>

    <input 
      type="text"
      value="https://aerivue.onrender.com/lookup?number=6396129529&apikey=YOUR_API_KEY"
      style="width:100%;padding:6px;font-family:monospace"
      readonly
      onclick="this.select()"
    >
  </div>

</div>

  <!-- Test Lookup -->
  <div class="card">
    <h3>🔍 Test Number Lookup</h3>
    <div class="grid2">
      <div>
        <label>Phone Number</label>
        <input type="text" id="testNumber" placeholder="6396129529">
      </div>
      <div>
        <label>API Key</label>
        <input type="text" id="testKey" placeholder="ak_...">
      </div>
    </div>
    <div style="margin-top:14px">
      <button class="btn btn-primary" onclick="testLookup()">Lookup</button>
    </div>
    <pre id="lookupResult" style="display:none;margin-top:14px;background:#0f172a;border:1px solid #334155;border-radius:7px;padding:14px;font-size:.82rem;color:#a5b4fc;overflow-x:auto;white-space:pre-wrap;word-break:break-all"></pre>
  </div>
</div>

<script>
async function apiFetch(url, opts={}) {
  const res = await fetch(url, { ...opts, headers: {'Content-Type':'application/json', ...(opts.headers||{})} });
  return [res.status, await res.json()];
}

async function logout() {
  await apiFetch('/admin/logout', {method:'POST'});
  window.location.href = '/admin';
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = '<div class="msg '+(ok?'ok':'err')+'">'+text+'</div>';
  setTimeout(()=>el.innerHTML='', 5000);
}

async function loadMyKeys() {
  const [,data] = await apiFetch('/admin/api/my-keys');
  const tb = document.getElementById('myKeysTable');
  if(!data.keys?.length){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:#475569">No keys created yet</td></tr>';return;}
  tb.innerHTML = data.keys.map(k=>{
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    let status;
    if(!k.isActive) status='<span class="badge-red">Disabled</span>';
    else if(expired) status='<span class="badge-yellow">Expired</span>';
    else status='<span class="badge-green">Active</span>';
    const usage = k.usageLimit ? k.usageCount+'/'+k.usageLimit : k.usageCount+'/∞';
    return \`<tr>
      <td style="font-family:monospace;font-size:.75rem">\${k.key} <button class="btn-copy" onclick="copyText('\${k.key}')">Copy</button></td>
      <td>\${k.label||'-'}</td>
      <td>\${exp.toLocaleDateString()}</td>
      <td>\${usage}</td>
      <td>\${status}</td>
      <td><button class="btn btn-danger" onclick="deleteKey('\${k._id}')">Delete</button></td>
    </tr>\`;
  }).join('');
}

function copyText(t) {
  navigator.clipboard.writeText(t);
}

async function createKey() {
  const label = document.getElementById('keyLabel').value.trim();
  const days = parseInt(document.getElementById('keyExpiry').value);
  const usageLimit = parseInt(document.getElementById('keyLimit').value)||0;
  const [status,data] = await apiFetch('/admin/api/my-keys', {
    method:'POST',
    body: JSON.stringify({label, days, usageLimit})
  });
  if(status===201) {
    document.getElementById('newKeyVal').textContent = data.key;
    document.getElementById('newKeyDisplay').style.display='block';
    document.getElementById('keyLabel').value='';
    loadMyKeys();
  } else {
    showMsg('keyMsg', data.error||'Failed', false);
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
  const key = document.getElementById('testKey').value.trim();
  if(!number||!key){alert('Enter number and API key');return;}
  const res = await fetch('/lookup?number='+encodeURIComponent(number), {headers:{'x-api-key':key}});
  const data = await res.json();
  const el = document.getElementById('lookupResult');
  el.style.display='block';
  el.textContent = JSON.stringify(data, null, 2);
}

// Load username
apiFetch('/admin/api/me').then(([,d])=>{
  document.getElementById('welcomeUser').textContent = d.username||'';
});

loadMyKeys();
</script>
</body></html>`;

// ─────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────

// GET /admin → login page
app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      if (isSuperAdmin(user.username)) return res.redirect("/admin/dashboard");
      return res.redirect("/admin/panel");
    } catch {}
  }
  res.send(superAdminLoginHtml());
});

// GET /admin/dashboard → super admin dashboard
app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => {
  res.send(superAdminDashboardHtml());
});

// GET /admin/panel → normal admin panel
app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.send(adminPanelHtml());
});

// POST /admin/login
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  // Check super admin
  if (username === process.env.SUPER_ADMIN_USERNAME) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = signToken({ username, role: "superadmin" });
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  // Check normal admin
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = signToken({ username, role: "admin" });
  res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

// POST /admin/logout
app.post("/admin/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// GET /admin/api/me
app.get("/admin/api/me", authMiddleware, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ─────────────────────────────────────────────
// SUPER ADMIN API ROUTES
// ─────────────────────────────────────────────

// GET /admin/api/stats
app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  const totalAdmins = await Admin.countDocuments();
  const totalKeys = await ApiKey.countDocuments();
  const activeKeys = await ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } });
  res.json({ totalAdmins, totalKeys, activeKeys });
});

// GET /admin/api/admins
app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const admins = await Admin.find({}, { password: 0 }).lean();
  // Add key counts
  const result = await Promise.all(admins.map(async a => ({
    ...a,
    keyCount: await ApiKey.countDocuments({ createdBy: a.username })
  })));
  res.json({ admins: result });
});

// POST /admin/api/admins
app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (username === process.env.SUPER_ADMIN_USERNAME) return res.status(400).json({ error: "Reserved username" });
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(409).json({ error: "Admin already exists" });
  const hashed = await bcrypt.hash(password, 10);
  await Admin.create({ username, password: hashed });
  res.status(201).json({ message: `Admin "${username}" created successfully` });
});

// DELETE /admin/api/admins/:username
app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (username === process.env.SUPER_ADMIN_USERNAME) return res.status(400).json({ error: "Cannot delete super admin" });
  const admin = await Admin.findOneAndDelete({ username });
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  await ApiKey.deleteMany({ createdBy: username });
  res.json({ message: `Admin "${username}" and all their keys deleted` });
});

// GET /admin/api/all-keys
app.get("/admin/api/all-keys", authMiddleware, superAdminOnly, async (req, res) => {
  const keys = await ApiKey.find().sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

// DELETE /admin/api/all-keys/:id
app.delete("/admin/api/all-keys/:id", authMiddleware, superAdminOnly, async (req, res) => {
  const key = await ApiKey.findByIdAndDelete(req.params.id);
  if (!key) return res.status(404).json({ error: "Key not found" });
  res.json({ message: "Key deleted" });
});

// ─────────────────────────────────────────────
// ADMIN API ROUTES (normal admins)
// ─────────────────────────────────────────────

// GET /admin/api/my-keys
app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

// POST /admin/api/my-keys
app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0 } = req.body;
  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000);
  const key = generateApiKey();
  await ApiKey.create({
    key,
    label: label || "",
    createdBy: req.user.username,
    expiresAt,
    usageLimit: usageLimit > 0 ? usageLimit : null,
  });
  res.status(201).json({ key, expiresAt, message: "API key created" });
});

// DELETE /admin/api/my-keys/:id
app.delete("/admin/api/my-keys/:id", authMiddleware, async (req, res) => {
  const filter = { _id: req.params.id };
  // Normal admins can only delete their own keys; super admin can delete any
  if (!isSuperAdmin(req.user.username)) filter.createdBy = req.user.username;
  const key = await ApiKey.findOneAndDelete(filter);
  if (!key) return res.status(404).json({ error: "Key not found or unauthorized" });
  res.json({ message: "Key deleted" });
});

// ─────────────────────────────────────────────
// PUBLIC LOOKUP ROUTE
// ─────────────────────────────────────────────

app.get("/lookup", async (req, res) => {
  const { number } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;

  if (!number) return res.status(400).json({ error: "number query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required (x-api-key header or ?apikey=)" });

  // Validate key
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return res.status(401).json({ error: "Invalid API key" });
  if (!keyDoc.isActive) return res.status(403).json({ error: "API key is disabled" });
  if (keyDoc.expiresAt < new Date()) return res.status(403).json({ error: "API key expired" });
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit) {
    return res.status(429).json({ error: "API key usage limit reached" });
  }

  try {
    // Call upstream API
    const upstreamUrl = `${process.env.UPSTREAM_API_URL}?number=${encodeURIComponent(number)}`;
    const response = await axios.get(upstreamUrl, { timeout: 10000 });

    // Update usage
    await ApiKey.findByIdAndUpdate(keyDoc._id, {
      $inc: { usageCount: 1 },
      lastUsedAt: new Date(),
    });

    const data = response.data;

// owner override
data.owner = "@aerivue";

if (data.result && typeof data.result === "object") {
  data.result.owner = "@aerivue";
}

return res.json(data);
  } catch (err) {
    if (err.response) {
      return res.status(err.response.status).json(err.response.data);
    }
    return res.status(500).json({ error: "Upstream API error"});
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
      console.log(`🚀 Server running on http://localhost:${process.env.PORT || 3000}`);
      console.log(`🔐 Super Admin: http://localhost:${process.env.PORT || 3000}/admin`);
      console.log(`🔍 Lookup API: http://localhost:${process.env.PORT || 3000}/lookup?number=XXXXXXXXXX`);
    });
  } catch (err) {
    console.error("❌ Startup error:");
    process.exit(1);
  }
}

start();
