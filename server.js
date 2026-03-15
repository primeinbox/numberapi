require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const { imgtotextai } = require('goodai'); 

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// API REGISTRY
// ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send(superAdminDashboardHtml());
});

app.listen(port, () => console.log(`Dashboard running at http://localhost:${port}`));

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
    label: "Image Generator",
    prefix: "img_",
    route: "/generate",
    paramName: "prompt",
    envKey: "UPSTREAM_IMAGE_API_URL",
    description: "AI logo & image generation",
    icon: "🎨",
    asyncGenerate: true,
    checkEnvKey: "UPSTREAM_IMAGE_CHECK_URL",
  },
];

// ─────────────────────────────────────────────
// SCHEMAS
// ─────────────────────────────────────────────

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  allowedTypes: {
    type: [String],
    enum: [...API_REGISTRY.map((a) => a.type), "all"],
    default: ["all"],
  },
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

// Session schema for device tracking
const SessionSchema = new mongoose.Schema({
  username: { type: String, required: true },
  sessionId: { type: String, unique: true, required: true },
  userAgent: { type: String, default: "" },
  ip: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
});

const Admin = mongoose.model("Admin", AdminSchema);
const ApiKey = mongoose.model("ApiKey", ApiKeySchema);
const Session = mongoose.model("Session", SessionSchema);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function generateApiKey(type = "number") {
  const api = API_REGISTRY.find((a) => a.type === type);
  const prefix = api ? api.prefix : "ak_";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let key = prefix;
  for (let i = 0; i < 32; i++) key += chars[Math.floor(Math.random() * chars.length)];
  return key;
}

function signToken(payload, sessionId) {
  return jwt.sign({ ...payload, sessionId }, process.env.JWT_SECRET, { expiresIn: "8h" });
}

function isSuperAdmin(username) {
  return username === process.env.SUPER_ADMIN_USERNAME;
}

function getClientIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown";
}

function parseDevice(ua = "") {
  if (!ua) return "Unknown Device";
  if (/mobile/i.test(ua)) return "📱 Mobile";
  if (/tablet/i.test(ua)) return "📟 Tablet";
  return "🖥 Desktop";
}

async function createSession(username, req) {
  const sessionId = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + 8 * 3600 * 1000);
  await Session.create({
    username,
    sessionId,
    userAgent: req.headers["user-agent"] || "",
    ip: getClientIp(req),
    expiresAt,
  });
  return sessionId;
}

async function touchSession(sessionId) {
  await Session.findOneAndUpdate({ sessionId }, { lastSeen: new Date() });
}

async function removeSession(sessionId) {
  await Session.findOneAndDelete({ sessionId });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    // Update lastSeen
    if (req.user.sessionId) {
      await touchSession(req.user.sessionId);
    }
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
  if (keyDoc.keyType !== requiredType) return { error: `This key is not authorized for ${requiredType} lookups`, status: 403 };
  if (keyDoc.expiresAt < new Date()) return { error: "API key expired", status: 403 };
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit) return { error: "API key usage limit reached", status: 429 };
  return { keyDoc };
}

async function incrementUsage(keyId) {
  await ApiKey.findByIdAndUpdate(keyId, { $inc: { usageCount: 1 }, lastUsedAt: new Date() });
}

// ─────────────────────────────────────────────
// DESIGN SYSTEM — Anime Minimalist Dark
// ─────────────────────────────────────────────

const CSS_VARS = `
:root {
  --bg: #08090e;
  --bg1: #0d0f1a;
  --bg2: #111422;
  --surface: #13162a;
  --surface2: #181c30;
  --border: #1e2340;
  --border2: #252b4a;
  --accent: #6c8aff;
  --accent2: #a78bfa;
  --accent3: #38d9f5;
  --green: #3dfaaa;
  --red: #ff5f7e;
  --yellow: #ffd166;
  --pink: #ff6eb4;
  --text: #e8eaf6;
  --text2: #8b90b8;
  --text3: #4a5080;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Sora', sans-serif;
}
`;

const BASE_CSS = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Sora:wght@300;400;500;600;700&display=swap');

*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{background:var(--bg);font-family:var(--sans);color:var(--text);min-height:100vh;font-size:14px}

body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 60% 40% at 80% 0%, rgba(108,138,255,.07) 0%, transparent 60%),
    radial-gradient(ellipse 40% 30% at 10% 100%, rgba(167,139,250,.05) 0%, transparent 60%);
}

::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
a{color:var(--accent);text-decoration:none}

/* TOPBAR */
.topbar{
  background:rgba(13,15,26,.85);
  border-bottom:1px solid var(--border);
  padding:0 28px;height:56px;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
}
.topbar-brand{display:flex;align-items:center;gap:12px}
.brand-mark{
  width:30px;height:30px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:700;color:#fff;letter-spacing:-.5px;
  box-shadow:0 0 20px rgba(108,138,255,.3);
}
.brand-name{font-size:.9rem;font-weight:700;letter-spacing:.1em;color:var(--text);text-transform:uppercase}
.brand-tag{
  font-size:.6rem;font-family:var(--mono);
  background:var(--surface2);color:var(--text3);
  padding:2px 8px;border-radius:99px;border:1px solid var(--border);
  letter-spacing:.1em;text-transform:uppercase;
}
.topbar-right{display:flex;align-items:center;gap:10px}
.user-pill{
  display:flex;align-items:center;gap:8px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:99px;padding:5px 14px 5px 8px;
  font-size:.75rem;color:var(--text2);
}
.user-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}

/* LAYOUT */
.layout{display:flex;min-height:calc(100vh - 56px);position:relative;z-index:1}
.sidebar{
  width:220px;flex-shrink:0;
  background:rgba(13,15,26,.6);
  border-right:1px solid var(--border);
  padding:20px 12px;
  position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto;
}
.main{flex:1;padding:28px;overflow:hidden}

/* SIDEBAR NAV */
.nav-section{margin-bottom:24px}
.nav-section-label{font-size:.62rem;font-family:var(--mono);color:var(--text3);letter-spacing:.15em;text-transform:uppercase;padding:0 8px;margin-bottom:8px}
.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 12px;border-radius:8px;
  color:var(--text2);font-size:.8rem;font-weight:500;
  cursor:pointer;transition:all .15s;border:1px solid transparent;
  margin-bottom:2px;
}
.nav-item:hover{background:var(--surface);color:var(--text);border-color:var(--border)}
.nav-item.active{background:var(--surface2);color:var(--accent);border-color:var(--border2)}
.nav-item .nav-icon{font-size:1rem;width:20px;text-align:center;flex-shrink:0}
.nav-badge{margin-left:auto;font-size:.62rem;font-family:var(--mono);background:var(--accent);color:#fff;padding:1px 7px;border-radius:99px}

/* CONTAINER */
.container{max-width:1100px}

/* CARDS */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:14px;
  padding:22px 24px;
  margin-bottom:18px;
  position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(108,138,255,.03) 0%,transparent 50%);
  pointer-events:none;border-radius:14px;
}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.card-title{font-size:.8rem;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;letter-spacing:.03em;text-transform:uppercase}
.card-title .icon{font-size:1rem}

/* STAT CARDS */
.stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}
.stat-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:20px;position:relative;overflow:hidden;
}
.stat-card::after{
  content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--accent),var(--accent2));
}
.stat-num{
  font-size:2rem;font-weight:700;font-family:var(--mono);
  background:linear-gradient(135deg,var(--accent),var(--accent3));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
  line-height:1;
}
.stat-label{color:var(--text3);font-size:.7rem;margin-top:8px;font-family:var(--mono);letter-spacing:.08em;text-transform:uppercase}
.stat-sub{color:var(--text2);font-size:.72rem;margin-top:3px}

/* GRID */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

/* FORM */
.field{margin-bottom:14px}
.field label{display:block;color:var(--text3);font-size:.67rem;margin-bottom:6px;font-family:var(--mono);letter-spacing:.1em;text-transform:uppercase}
input,select,textarea{
  width:100%;padding:9px 13px;
  background:var(--bg1);
  border:1px solid var(--border);
  border-radius:8px;color:var(--text);
  font-size:.82rem;font-family:var(--sans);
  transition:border-color .15s, box-shadow .15s;
}
input:focus,select:focus,textarea:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(108,138,255,.1);
}
select option{background:var(--surface)}
.checkbox-group{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.cb-item{
  display:flex;align-items:center;gap:7px;
  background:var(--bg1);border:1px solid var(--border);
  border-radius:8px;padding:7px 12px;cursor:pointer;
  font-size:.78rem;color:var(--text2);transition:all .15s;
  user-select:none;
}
.cb-item:hover{border-color:var(--border2);color:var(--text)}
.cb-item.checked{border-color:var(--accent);color:var(--accent);background:rgba(108,138,255,.08)}
.cb-item input{display:none}

/* BUTTONS */
.btn{
  padding:8px 18px;border:1px solid transparent;border-radius:8px;
  cursor:pointer;font-size:.78rem;font-weight:600;font-family:var(--sans);
  transition:all .15s;display:inline-flex;align-items:center;gap:6px;
  letter-spacing:.02em;
}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{background:#5a78ee;box-shadow:0 4px 16px rgba(108,138,255,.3);transform:translateY(-1px)}
.btn-green{background:rgba(61,250,170,.12);color:var(--green);border-color:rgba(61,250,170,.3)}
.btn-green:hover{background:rgba(61,250,170,.2);box-shadow:0 4px 12px rgba(61,250,170,.15)}
.btn-red{background:rgba(255,95,126,.1);color:var(--red);border-color:rgba(255,95,126,.25);font-size:.73rem;padding:5px 11px}
.btn-red:hover{background:rgba(255,95,126,.18)}
.btn-ghost{background:transparent;border-color:var(--border);color:var(--text2)}
.btn-ghost:hover{border-color:var(--border2);color:var(--text)}
.btn-sm{padding:5px 12px;font-size:.72rem}
.copy-btn{
  background:var(--bg2);color:var(--text3);
  border:1px solid var(--border);border-radius:5px;
  font-size:.65rem;padding:2px 8px;cursor:pointer;
  font-family:var(--mono);transition:all .15s;
}
.copy-btn:hover{color:var(--text);border-color:var(--border2)}

/* TABLE */
.table-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.78rem;min-width:580px}
thead th{
  padding:10px 14px;color:var(--text3);
  border-bottom:1px solid var(--border);
  font-weight:600;font-size:.65rem;text-transform:uppercase;
  letter-spacing:.08em;background:var(--bg2);white-space:nowrap;
}
tbody td{
  padding:11px 14px;border-bottom:1px solid var(--border);
  color:var(--text2);vertical-align:middle;
}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .1s}
tbody tr:hover td{background:rgba(108,138,255,.03)}

/* BADGES */
.badge{padding:2px 9px;border-radius:99px;font-size:.65rem;font-weight:600;font-family:var(--mono);white-space:nowrap}
.badge-green{background:rgba(61,250,170,.1);color:var(--green);border:1px solid rgba(61,250,170,.2)}
.badge-red{background:rgba(255,95,126,.1);color:var(--red);border:1px solid rgba(255,95,126,.2)}
.badge-yellow{background:rgba(255,209,102,.1);color:var(--yellow);border:1px solid rgba(255,209,102,.2)}
.badge-blue{background:rgba(108,138,255,.1);color:var(--accent);border:1px solid rgba(108,138,255,.2)}
.badge-purple{background:rgba(167,139,250,.1);color:var(--accent2);border:1px solid rgba(167,139,250,.2)}
.badge-cyan{background:rgba(56,217,245,.1);color:var(--accent3);border:1px solid rgba(56,217,245,.2)}

/* TYPE BADGES */
.badge-type-number{background:rgba(108,138,255,.1);color:var(--accent);border:1px solid rgba(108,138,255,.2)}
.badge-type-rto{background:rgba(61,250,170,.1);color:var(--green);border:1px solid rgba(61,250,170,.2)}
.badge-type-image{background:rgba(167,139,250,.1);color:var(--accent2);border:1px solid rgba(167,139,250,.2)}

/* MESSAGES */
.msg{padding:9px 13px;border-radius:8px;font-size:.78rem;margin-top:10px;display:flex;align-items:center;gap:8px}
.msg-ok{background:rgba(61,250,170,.07);color:var(--green);border:1px solid rgba(61,250,170,.15)}
.msg-err{background:rgba(255,95,126,.07);color:var(--red);border:1px solid rgba(255,95,126,.15)}

/* KEY DISPLAY */
.key-box{
  background:var(--bg);border:1px solid rgba(108,138,255,.3);
  border-radius:8px;padding:12px 16px;
  font-family:var(--mono);font-size:.78rem;color:var(--accent3);
  word-break:break-all;margin-top:10px;
  box-shadow:0 0 20px rgba(108,138,255,.08);
}

/* SESSION CARD */
.session-item{
  background:var(--bg1);border:1px solid var(--border);
  border-radius:10px;padding:12px 16px;
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:8px;
}
.session-info{display:flex;flex-direction:column;gap:3px}
.session-device{font-size:.8rem;color:var(--text);font-weight:500}
.session-meta{font-size:.7rem;color:var(--text3);font-family:var(--mono)}

/* ENDPOINT BOX */
.ep-item{
  background:var(--bg1);border:1px solid var(--border);
  border-radius:8px;padding:12px 14px;margin-bottom:8px;
}
.ep-method{color:var(--green);font-family:var(--mono);font-size:.73rem;font-weight:700;margin-right:8px}
.ep-url{color:var(--accent);font-family:var(--mono);font-size:.73rem}
.ep-prefix{color:var(--text3);font-size:.68rem;font-family:var(--mono);margin-top:4px}

/* PRE */
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;font-family:var(--mono);font-size:.73rem;color:#a5b4fc;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.65}

/* SPINNER */
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:rot .6s linear infinite;vertical-align:middle}
@keyframes rot{to{transform:rotate(360deg)}}

/* DIVIDER */
.divider{height:1px;background:var(--border);margin:18px 0}

/* MOBILE */
@media(max-width:900px){
  .sidebar{display:none}
  .main{padding:20px 16px}
  .stats-grid{grid-template-columns:1fr 1fr}
  .grid2,.grid3{grid-template-columns:1fr}
}
@media(max-width:600px){
  .stats-grid{grid-template-columns:1fr}
  .topbar{padding:0 16px}
  .brand-tag{display:none}
}
`;

// ─────────────────────────────────────────────
// LOGIN PAGE
// ─────────────────────────────────────────────

const loginHtml = () => `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aerivue</title>
<style>
${CSS_VARS}${BASE_CSS}
body{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-wrap{width:100%;max-width:380px;padding:20px;position:relative;z-index:1}
.login-top{text-align:center;margin-bottom:32px}
.login-logo{
  width:52px;height:52px;background:linear-gradient(135deg,var(--accent),var(--accent2));
  border-radius:14px;display:flex;align-items:center;justify-content:center;
  font-size:22px;margin:0 auto 14px;
  box-shadow:0 8px 32px rgba(108,138,255,.4);
}
.login-top h1{font-size:1.4rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text)}
.login-top p{color:var(--text3);font-size:.72rem;font-family:var(--mono);margin-top:4px;letter-spacing:.06em;text-transform:uppercase}
.login-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:16px;padding:28px;
}
.login-card .field{margin-bottom:0}
.login-submit{
  width:100%;margin-top:20px;padding:11px;
  background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
  color:#fff;border:none;border-radius:9px;font-size:.85rem;
  cursor:pointer;font-weight:700;font-family:var(--sans);
  letter-spacing:.04em;transition:all .2s;
  box-shadow:0 4px 20px rgba(108,138,255,.25);
}
.login-submit:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(108,138,255,.4)}
.err-msg{display:none;margin-top:12px;text-align:center}
.login-footer{text-align:center;margin-top:20px;font-size:.65rem;font-family:var(--mono);color:var(--text3);letter-spacing:.06em;text-transform:uppercase}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-top">
    <div class="login-logo">⚡</div>
    <h1>Aerivue</h1>
    <p>API Management System</p>
  </div>
  <div class="login-card">
    <div class="field" style="margin-bottom:12px">
      <label>Username</label>
      <input type="text" id="usr" placeholder="Enter username" autocomplete="username">
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" id="pwd" placeholder="••••••••" autocomplete="current-password">
    </div>
    <button class="login-submit" onclick="doLogin()">Sign In →</button>
    <div id="err" class="msg msg-err err-msg"></div>
  </div>
  <div class="login-footer">Secure · Private · Fast</div>
</div>
<script>
async function doLogin() {
  const username = document.getElementById('usr').value.trim();
  const password = document.getElementById('pwd').value;
  const errEl = document.getElementById('err');
  errEl.style.display = 'none';
  if (!username || !password) { errEl.textContent = '✗ Fill all fields'; errEl.style.display = 'flex'; return; }
  const res = await fetch('/admin/login', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (res.ok) {
    window.location.href = data.role === 'superadmin' ? '/admin/dashboard' : '/admin/panel';
  } else {
    errEl.textContent = '✗ ' + (data.error || 'Login failed');
    errEl.style.display = 'flex';
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
<title>Super Admin · Aerivue</title>
<style>
${CSS_VARS}${BASE_CSS}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-brand">
    <div class="brand-mark">A</div>
    <span class="brand-name">Aerivue</span>
    <span class="brand-tag">Super Admin</span>
  </div>
  <div class="topbar-right">
    <div class="user-pill">
      <span class="user-dot"></span>
      <span id="topUsername" style="font-weight:600;color:var(--text)"></span>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="logout()">Logout</button>
  </div>
</div>

<div class="layout">
  <aside class="sidebar">
    <div class="nav-section">
      <div class="nav-section-label">Main</div>
      <div class="nav-item active" onclick="nav('overview',this)">
        <span class="nav-icon">◈</span> Overview
      </div>
      <div class="nav-item" onclick="nav('sessions',this)">
        <span class="nav-icon">⊙</span> Sessions
        <span class="nav-badge" id="sideSessionBadge">—</span>
      </div>
    </div>
    <div class="nav-section">
      <div class="nav-section-label">Management</div>
      <div class="nav-item" onclick="nav('admins',this)">
        <span class="nav-icon">◎</span> Admins
      </div>
      <div class="nav-item" onclick="nav('keys',this)">
        <span class="nav-icon">◆</span> All Keys
      </div>
    </div>
  </aside>

  <main class="main">
    <!-- OVERVIEW -->
    <div id="pane-overview" class="pane">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-num" id="s-admins">—</div>
          <div class="stat-label">Total Admins</div>
        </div>
        <div class="stat-card">
          <div class="stat-num" id="s-keys">—</div>
          <div class="stat-label">Total Keys</div>
        </div>
        <div class="stat-card">
          <div class="stat-num" id="s-active">—</div>
          <div class="stat-label">Active Keys</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◈</span> My Active Sessions</div>
        </div>
        <div id="mySessions">Loading...</div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◈</span> API Endpoints</div>
        </div>
        <div id="epList"></div>
      </div>
    </div>

    <!-- SESSIONS -->
    <div id="pane-sessions" class="pane" style="display:none">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">⊙</span> All Active Sessions</div>
          <button class="btn btn-ghost btn-sm" onclick="loadAllSessions()">↺ Refresh</button>
        </div>
        <div id="allSessionsWrap"></div>
      </div>
    </div>

    <!-- ADMINS -->
    <div id="pane-admins" class="pane" style="display:none">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">+</span> Create Admin</div>
        </div>
        <div class="grid2">
          <div class="field"><label>Username</label><input type="text" id="newAdminUser" placeholder="admin_name"></div>
          <div class="field"><label>Password</label><input type="password" id="newAdminPass" placeholder="••••••••"></div>
        </div>
        <div class="field">
          <label>API Access</label>
          <div class="checkbox-group" id="accessCheckboxes">
            <div class="cb-item checked" data-type="all" onclick="toggleCb(this)">
              <span>✦ All Access</span>
            </div>
            ${API_REGISTRY.map(a => `<div class="cb-item" data-type="${a.type}" onclick="toggleCb(this)">
              <span>${a.icon} ${a.label}</span>
            </div>`).join("")}
          </div>
        </div>
        <div style="margin-top:14px">
          <button class="btn btn-primary" onclick="createAdmin()">Create Admin</button>
        </div>
        <div id="adminMsg"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◎</span> All Admins</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Username</th><th>Access</th><th>Keys</th><th>Sessions</th><th>Created</th><th></th></tr></thead>
            <tbody id="adminTable"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ALL KEYS -->
    <div id="pane-keys" class="pane" style="display:none">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◆</span> All API Keys</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Key</th><th>Label</th><th>Admin</th><th>Type</th><th>Expires</th><th>Usage</th><th>Status</th><th></th></tr></thead>
            <tbody id="allKeysTable"></tbody>
          </table>
        </div>
      </div>
    </div>
  </main>
</div>

<script>
const API_TYPES = ${JSON.stringify(API_REGISTRY.map(a => ({ type: a.type, label: a.label, icon: a.icon, route: a.route, paramName: a.paramName, prefix: a.prefix })))};

async function apiFetch(url, opts={}) {
  const r = await fetch(url, {...opts, headers:{\'Content-Type\':\'application/json\',...(opts.headers||{})}});
  return [r.status, await r.json()];
}

async function logout() {
  await apiFetch(\'/admin/logout\', {method:\'POST\'});
  window.location.href = \'/admin\';
}

function nav(name, el) {
  document.querySelectorAll(\'.nav-item\').forEach(i => i.classList.remove(\'active\'));
  el.classList.add(\'active\');
  document.querySelectorAll(\'.pane\').forEach(p => p.style.display = \'none\');
  document.getElementById(\'pane-\'+name).style.display = \'block\';
  if(name===\'overview\') loadOverview();
  if(name===\'sessions\') loadAllSessions();
  if(name===\'admins\') loadAdmins();
  if(name===\'keys\') loadAllKeys();
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = \'<div class="msg \'+(ok?\'msg-ok\':\'msg-err\')+\'">\'+(ok?\'✓\':\'✗\')+\' \'+text+\'</div>\';
  setTimeout(()=>el.innerHTML=\'\',4000);
}

function typeBadge(type) {
  const a = API_TYPES.find(x=>x.type===type);
  return \'<span class="badge badge-type-\'+type+\'">\'+(a?a.icon+\' \'+a.label:type)+\'</span>\';
}

function accessBadges(types) {
  if(!types||types.includes(\'all\')) return \'<span class="badge badge-purple">✦ All</span>\';
  return types.map(t => typeBadge(t)).join(\' \');
}

// Access checkbox logic
function toggleCb(el) {
  const all = document.querySelector(\'[data-type="all"]\');
  if(el.dataset.type === \'all\') {
    // Select all
    document.querySelectorAll(\'#accessCheckboxes .cb-item\').forEach(c => c.classList.add(\'checked\'));
  } else {
    all.classList.remove(\'checked\');
    el.classList.toggle(\'checked\');
    // If none selected, re-check all
    const anyChecked = [...document.querySelectorAll(\'#accessCheckboxes .cb-item:not([data-type="all"])\')].some(c=>c.classList.contains(\'checked\'));
    if(!anyChecked) all.classList.add(\'checked\');
  }
}

function getSelectedAccess() {
  const all = document.querySelector(\'[data-type="all"]\');
  if(all.classList.contains(\'checked\')) return [\'all\'];
  return [...document.querySelectorAll(\'#accessCheckboxes .cb-item:not([data-type="all"])\')].filter(c=>c.classList.contains(\'checked\')).map(c=>c.dataset.type);
}

async function loadOverview() {
  const [,stats] = await apiFetch(\'/admin/api/stats\');
  document.getElementById(\'s-admins\').textContent = stats.totalAdmins ?? \'—\';
  document.getElementById(\'s-keys\').textContent = stats.totalKeys ?? \'—\';
  document.getElementById(\'s-active\').textContent = stats.activeKeys ?? \'—\';

  // my sessions
  const [,sessData] = await apiFetch(\'/admin/api/sessions/me\');
  const msEl = document.getElementById(\'mySessions\');
  if(!sessData.sessions?.length) { msEl.innerHTML=\'<p style="color:var(--text3);font-size:.78rem">No active sessions.</p>\'; }
  else {
    msEl.innerHTML = sessData.sessions.map(s => sessionItem(s, true)).join(\'\');
  }

  // endpoints
  document.getElementById(\'epList\').innerHTML = API_TYPES.map(a=>\`
    <div class="ep-item">
      <span class="ep-method">GET</span><span class="ep-url">\${a.route}?\${a.paramName}=VALUE&apikey=YOUR_KEY</span>
      <div class="ep-prefix">Prefix: \${a.prefix}...</div>
    </div>\`).join(\'\');

  // sidebar badge
  const [,allSess] = await apiFetch(\'/admin/api/sessions/all\');
  const totalSessions = allSess.total || 0;
  document.getElementById(\'sideSessionBadge\').textContent = totalSessions;
}

function sessionItem(s, isMe=false) {
  const device = parseDevice(s.userAgent);
  const since = new Date(s.createdAt).toLocaleString();
  const seen = new Date(s.lastSeen).toLocaleString();
  return \`<div class="session-item">
    <div class="session-info">
      <div class="session-device">\${device}</div>
      <div class="session-meta">IP: \${s.ip} · Login: \${since}</div>
      <div class="session-meta">Last seen: \${seen}</div>
    </div>
    <button class="btn btn-red btn-sm" onclick="revokeSession(\'\${s._id}\')">Revoke</button>
  </div>\`;
}

function parseDevice(ua=\'\') {
  if(!ua) return \'🖥 Unknown\';
  if(/mobile/i.test(ua)) return \'📱 Mobile\';
  if(/tablet/i.test(ua)) return \'📟 Tablet\';
  return \'🖥 Desktop\';
}

async function revokeSession(id) {
  if(!confirm(\'Revoke this session?\')) return;
  const [,d] = await apiFetch(\'/admin/api/sessions/\'+id, {method:\'DELETE\'});
  loadOverview(); loadAllSessions();
}

async function loadAllSessions() {
  const [,data] = await apiFetch(\'/admin/api/sessions/all\');
  const wrap = document.getElementById(\'allSessionsWrap\');
  if(!data.byUser) { wrap.innerHTML=\'<p style="color:var(--text3);font-size:.78rem;padding:8px">No active sessions.</p>\'; return; }
  document.getElementById(\'sideSessionBadge\').textContent = data.total || 0;
  let html = \'\';
  for(const [user, sessions] of Object.entries(data.byUser)) {
    html += \`<div style="margin-bottom:20px">
      <div style="font-size:.72rem;font-family:var(--mono);color:var(--text3);letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px">
        ◎ \${user} <span class="badge badge-blue">\${sessions.length} session\${sessions.length>1?\'s\':\'\'}</span>
        \${user !== \'${process.env.SUPER_ADMIN_USERNAME}\' ? \'<button class="btn btn-red" onclick="revokeAllForUser(\\\'\' + user + \'\\\')">Revoke All</button>\' : \'\'}
      </div>
      \${sessions.map(s=>sessionItem(s)).join(\'\')}
    </div>\`;
  }
  wrap.innerHTML = html || \'<p style="color:var(--text3);font-size:.78rem;padding:8px">No active sessions.</p>\';
}

async function revokeAllForUser(username) {
  if(!confirm(\'Revoke all sessions for \'+username+\'?\')) return;
  await apiFetch(\'/admin/api/sessions/user/\'+username, {method:\'DELETE\'});
  loadAllSessions();
}

async function loadAdmins() {
  const [,data] = await apiFetch(\'/admin/api/admins\');
  const tb = document.getElementById(\'adminTable\');
  if(!data.admins?.length) { tb.innerHTML=\'<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:20px">No admins yet</td></tr>\'; return; }
  tb.innerHTML = data.admins.map(a=>\`<tr>
    <td style="font-weight:600;color:var(--text)">\${a.username}</td>
    <td>\${accessBadges(a.allowedTypes)}</td>
    <td><span class="badge badge-blue">\${a.keyCount}</span></td>
    <td><span class="badge \${a.sessionCount>0?\'badge-green\':\'badge-yellow\'}">\${a.sessionCount} online</span></td>
    <td style="font-family:var(--mono);font-size:.68rem;color:var(--text3)">\${new Date(a.createdAt).toLocaleDateString()}</td>
    <td><button class="btn btn-red" onclick="deleteAdmin(\'\${a.username}\')">Delete</button></td>
  </tr>\`).join(\'\');
}

async function createAdmin() {
  const username = document.getElementById(\'newAdminUser\').value.trim();
  const password = document.getElementById(\'newAdminPass\').value;
  const allowedTypes = getSelectedAccess();
  if(!username||!password) return showMsg(\'adminMsg\',\'Fill all fields\',false);
  const [status,data] = await apiFetch(\'/admin/api/admins\', {method:\'POST\', body:JSON.stringify({username,password,allowedTypes})});
  showMsg(\'adminMsg\', data.message||data.error, status===201);
  if(status===201) {
    document.getElementById(\'newAdminUser\').value=\'\';
    document.getElementById(\'newAdminPass\').value=\'\';
    loadAdmins(); loadOverview();
  }
}

async function deleteAdmin(username) {
  if(!confirm(\'Delete admin "\'+username+\'" and ALL their API keys?\')) return;
  const [status,data] = await apiFetch(\'/admin/api/admins/\'+username, {method:\'DELETE\'});
  showMsg(\'adminMsg\', data.message||data.error, status===200);
  loadAdmins(); loadOverview();
}

async function loadAllKeys() {
  const [,data] = await apiFetch(\'/admin/api/all-keys\');
  const tb = document.getElementById(\'allKeysTable\');
  if(!data.keys?.length) { tb.innerHTML=\'<tr><td colspan="8" style="text-align:center;color:var(--text3);padding:20px">No keys yet</td></tr>\'; return; }
  tb.innerHTML = data.keys.map(k=>{
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    const st = (!k.isActive||expired) ? \'<span class="badge badge-red">\'+(expired?\'Expired\':\'Off\')+\'</span>\' : \'<span class="badge badge-green">Active</span>\';
    const use = k.usageLimit ? k.usageCount+\'/\'+k.usageLimit : k.usageCount+\'/∞\';
    return \`<tr>
      <td style="font-family:var(--mono);font-size:.68rem;color:var(--accent3)">\${k.key.substring(0,16)}... <button class="copy-btn" onclick="copy(\'\${k.key}\')">copy</button></td>
      <td style="color:var(--text2)">\${k.label||\'—\'}</td>
      <td style="font-weight:600;color:var(--text)">\${k.createdBy}</td>
      <td>\${typeBadge(k.keyType)}</td>
      <td style="font-family:var(--mono);font-size:.68rem">\${exp.toLocaleDateString()}</td>
      <td style="font-family:var(--mono)">\${use}</td>
      <td>\${st}</td>
      <td><button class="btn btn-red" onclick="superDeleteKey(\'\${k._id}\')">Delete</button></td>
    </tr>\`;
  }).join(\'\');
}

async function superDeleteKey(id) {
  if(!confirm(\'Delete this API key?\')) return;
  const [,d] = await apiFetch(\'/admin/api/all-keys/\'+id, {method:\'DELETE\'});
  loadAllKeys(); loadOverview();
}

function copy(t) { navigator.clipboard.writeText(t); }

apiFetch(\'/admin/api/me\').then(([,d])=>{
  document.getElementById(\'topUsername\').textContent = d.username||\'\';
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
<title>Admin Panel · Aerivue</title>
<style>
${CSS_VARS}${BASE_CSS}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-brand">
    <div class="brand-mark">A</div>
    <span class="brand-name">Aerivue</span>
    <span class="brand-tag">Admin</span>
  </div>
  <div class="topbar-right">
    <div class="user-pill">
      <span class="user-dot" style="background:var(--green)"></span>
      <span id="topUsername" style="font-weight:600;color:var(--text)"></span>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="logout()">Logout</button>
  </div>
</div>

<div class="layout">
  <aside class="sidebar">
    <div class="nav-section">
      <div class="nav-section-label">Main</div>
      <div class="nav-item active" onclick="nav('keys',this)">
        <span class="nav-icon">◆</span> My Keys
      </div>
      <div class="nav-item" onclick="nav('sessions',this)">
        <span class="nav-icon">⊙</span> My Sessions
      </div>
      <div class="nav-item" onclick="nav('test',this)">
        <span class="nav-icon">◈</span> Test APIs
      </div>
    </div>
  </aside>

  <main class="main">
    <!-- MY KEYS -->
    <div id="pane-keys" class="pane">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">+</span> Generate API Key</div>
        </div>
        <div class="grid2">
          <div class="field">
            <label>API Type</label>
            <select id="keyType" onchange="updateTypeSelector()">
            </select>
          </div>
          <div class="field">
            <label>Label</label>
            <input type="text" id="keyLabel" placeholder="e.g. My App">
          </div>
          <div class="field">
            <label>Expires In</label>
            <select id="keyExpiry">
              <option value="1">1 Day</option>
              <option value="7" selected>7 Days</option>
              <option value="30">30 Days</option>
              <option value="90">90 Days</option>
              <option value="365">1 Year</option>
            </select>
          </div>
          <div class="field">
            <label>Usage Limit (0 = unlimited)</label>
            <input type="number" id="keyLimit" value="0" min="0">
          </div>
        </div>
        <button class="btn btn-green" onclick="createKey()">⚡ Generate Key</button>
        <div id="newKeyDisplay" style="display:none;margin-top:14px">
          <div style="font-size:.7rem;font-family:var(--mono);color:var(--text3);margin-bottom:4px;letter-spacing:.08em;text-transform:uppercase">Your Key — Save it now</div>
          <div class="key-box" id="newKeyVal"></div>
          <button class="copy-btn" style="margin-top:8px" onclick="copy(document.getElementById('newKeyVal').textContent)">Copy Key</button>
        </div>
        <div id="keyMsg"></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◆</span> My API Keys</div>
          <button class="btn btn-ghost btn-sm" onclick="loadMyKeys()">↺</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Key</th><th>Label</th><th>Type</th><th>Expires</th><th>Usage</th><th>Status</th><th></th></tr></thead>
            <tbody id="myKeysTable"></tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">◈</span> Endpoints Reference</div>
        </div>
        <div id="epRef"></div>
      </div>
    </div>

    <!-- SESSIONS -->
    <div id="pane-sessions" class="pane" style="display:none">
      <div class="card">
        <div class="card-header">
          <div class="card-title"><span class="icon">⊙</span> My Active Sessions</div>
          <button class="btn btn-ghost btn-sm" onclick="loadMySessions()">↺ Refresh</button>
        </div>
        <div id="mySessionsWrap">Loading...</div>
      </div>
    </div>

    <!-- TEST -->
    <div id="pane-test" class="pane" style="display:none">
      <div id="testCardsWrap"></div>
    </div>
  </main>
</div>

<script>
const API_TYPES = ${JSON.stringify(API_REGISTRY.map(a => ({ type: a.type, label: a.label, icon: a.icon, route: a.route, paramName: a.paramName, prefix: a.prefix })))};
let allowedTypes = [];

async function apiFetch(url, opts={}) {
  const r = await fetch(url, {...opts, headers:{'Content-Type':'application/json',...(opts.headers||{})}});
  return [r.status, await r.json()];
}

async function logout() {
  await apiFetch('/admin/logout', {method:'POST'});
  window.location.href = '/admin';
}

function nav(name, el) {
  document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.pane').forEach(p=>p.style.display='none');
  document.getElementById('pane-'+name).style.display='block';
  if(name==='keys') loadMyKeys();
  if(name==='sessions') loadMySessions();
  if(name==='test') buildTestCards();
}

function showMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.innerHTML = '<div class="msg '+(ok?'msg-ok':'msg-err')+'">'+(ok?'✓':'✗')+' '+text+'</div>';
  setTimeout(()=>el.innerHTML='',5000);
}

function typeBadge(type) {
  const a = API_TYPES.find(x=>x.type===type);
  return '<span class="badge badge-type-'+type+'">'+(a?a.icon+' '+a.label:type)+'</span>';
}

function copy(t) { navigator.clipboard.writeText(t); }

function parseDevice(ua='') {
  if(!ua) return '🖥 Unknown';
  if(/mobile/i.test(ua)) return '📱 Mobile';
  if(/tablet/i.test(ua)) return '📟 Tablet';
  return '🖥 Desktop';
}

async function loadMySessions() {
  const [,data] = await apiFetch('/admin/api/sessions/me');
  const wrap = document.getElementById('mySessionsWrap');
  if(!data.sessions?.length) { wrap.innerHTML='<p style="color:var(--text3);font-size:.78rem">No active sessions.</p>'; return; }
  wrap.innerHTML = data.sessions.map(s => \`<div class="session-item">
    <div class="session-info">
      <div class="session-device">\${parseDevice(s.userAgent)}</div>
      <div class="session-meta">IP: \${s.ip} · Login: \${new Date(s.createdAt).toLocaleString()}</div>
      <div class="session-meta">Last seen: \${new Date(s.lastSeen).toLocaleString()}</div>
    </div>
    <button class="btn btn-red btn-sm" onclick="revokeMySession('\${s._id}')">Revoke</button>
  </div>\`).join('');
}

async function revokeMySession(id) {
  if(!confirm('Revoke this session?')) return;
  await apiFetch('/admin/api/sessions/'+id, {method:'DELETE'});
  loadMySessions();
}

async function loadMyKeys() {
  const [,data] = await apiFetch('/admin/api/my-keys');
  const tb = document.getElementById('myKeysTable');
  if(!data.keys?.length) {
    tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:20px">No keys yet</td></tr>'; return;
  }
  tb.innerHTML = data.keys.map(k=>{
    const exp = new Date(k.expiresAt);
    const expired = exp < new Date();
    let st;
    if(!k.isActive) st='<span class="badge badge-red">Off</span>';
    else if(expired) st='<span class="badge badge-yellow">Expired</span>';
    else st='<span class="badge badge-green">Active</span>';
    const use = k.usageLimit ? k.usageCount+'/'+k.usageLimit : k.usageCount+'/∞';
    return \`<tr>
      <td style="font-family:var(--mono);font-size:.68rem;color:var(--accent3)">
        \${k.key.substring(0,16)}...
        <button class="copy-btn" onclick="copy('\${k.key}')">copy</button>
      </td>
      <td>\${k.label||'—'}</td>
      <td>\${typeBadge(k.keyType)}</td>
      <td style="font-family:var(--mono);font-size:.68rem">\${exp.toLocaleDateString()}</td>
      <td style="font-family:var(--mono)">\${use}</td>
      <td>\${st}</td>
      <td><button class="btn btn-red" onclick="deleteKey('\${k._id}')">Delete</button></td>
    </tr>\`;
  }).join('');
}

async function createKey() {
  const keyType = document.getElementById('keyType').value;
  const label = document.getElementById('keyLabel').value.trim();
  const days = parseInt(document.getElementById('keyExpiry').value);
  const usageLimit = parseInt(document.getElementById('keyLimit').value)||0;
  const [status,data] = await apiFetch('/admin/api/my-keys', {method:'POST', body:JSON.stringify({label,days,usageLimit,keyType})});
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
  if(!confirm('Delete this API key?')) return;
  const [status,data] = await apiFetch('/admin/api/my-keys/'+id, {method:'DELETE'});
  showMsg('keyMsg', data.message||data.error, status===200);
  loadMyKeys();
}

function buildTestCards() {
  const wrap = document.getElementById('testCardsWrap');
  const visible = API_TYPES.filter(a => allowedTypes.includes('all') || allowedTypes.includes(a.type));
  if(!visible.length) { wrap.innerHTML='<div class="card"><p style="color:var(--text3)">No API access granted.</p></div>'; return; }

  wrap.innerHTML = visible.map(a => {
    if(a.type === 'image') return \`
      <div class="card">
        <div class="card-title"><span class="icon">\${a.icon}</span> Test \${a.label}</div>
        <div class="grid2" style="margin-top:14px">
          <div class="field"><label>Prompt</label><input type="text" id="testPrompt" placeholder="e.g. futuristic lion"></div>
          <div class="field"><label>API Key (img_...)</label><input type="text" id="testImgKey" placeholder="img_..."></div>
        </div>
        <button class="btn btn-primary btn-sm" id="genBtn" onclick="testGenerate()">Generate</button>
        <div id="genResult" style="margin-top:14px"></div>
      </div>\`;
    return \`
      <div class="card">
        <div class="card-title"><span class="icon">\${a.icon}</span> Test \${a.label}</div>
        <div class="grid2" style="margin-top:14px">
          <div class="field"><label>\${a.paramName.toUpperCase()}</label><input type="text" id="test_\${a.type}_val" placeholder="\${a.paramName}..."></div>
          <div class="field"><label>API Key (\${a.prefix}...)</label><input type="text" id="test_\${a.type}_key" placeholder="\${a.prefix}..."></div>
        </div>
        <button class="btn btn-primary btn-sm" onclick="testGeneric('\${a.type}','\${a.route}','\${a.paramName}')">Test</button>
        <pre id="result_\${a.type}" style="display:none;margin-top:12px"></pre>
      </div>\`;
  }).join('');
}

async function testGeneric(type, route, paramName) {
  const val = document.getElementById('test_'+type+'_val').value.trim();
  const key = document.getElementById('test_'+type+'_key').value.trim();
  if(!val||!key) { alert('Fill both fields'); return; }
  const res = await fetch(route+'?'+paramName+'='+encodeURIComponent(val)+'&apikey='+encodeURIComponent(key));
  const data = await res.json();
  const el = document.getElementById('result_'+type);
  el.style.display='block';
  el.textContent = JSON.stringify(data,null,2);
}

async function testGenerate() {
  const prompt = document.getElementById('testPrompt').value.trim();
  const key = document.getElementById('testImgKey').value.trim();
  if(!prompt||!key){alert('Fill both fields');return;}
  const btn = document.getElementById('genBtn');
  const res = document.getElementById('genResult');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span> Generating...';
  res.innerHTML='<div style="color:var(--text2);font-size:.78rem">⏳ Starting...</div>';
  try {
    const r = await fetch('/generate?prompt='+encodeURIComponent(prompt)+'&apikey='+encodeURIComponent(key));
    const d = await r.json();
    if(!r.ok){res.innerHTML='<pre>'+JSON.stringify(d,null,2)+'</pre>';btn.disabled=false;btn.textContent='Generate';return;}
    const taskId = d.task_id;
    res.innerHTML='<div style="color:var(--text2);font-size:.78rem">Task: <code style="color:var(--accent)">'+taskId+'</code> — polling...</div>';
    let attempts=0;
    const poll=setInterval(async()=>{
      attempts++;
      const cr=await fetch('/generate/check?task_id='+encodeURIComponent(taskId)+'&apikey='+encodeURIComponent(key));
      const cd=await cr.json();
      if(cd.image_url){
        clearInterval(poll);
        res.innerHTML='<div style="color:var(--green);font-size:.78rem;margin-bottom:8px">✓ Ready</div><img src="'+cd.image_url+'" style="max-width:100%;border-radius:8px;border:1px solid var(--border)"><div style="margin-top:8px"><a href="'+cd.image_url+'" target="_blank" class="btn btn-primary btn-sm">Open Image</a></div>';
        btn.disabled=false;btn.textContent='Generate';
      } else if(attempts>30){
        clearInterval(poll);
        res.innerHTML='<div style="color:var(--yellow)">⚠ Timed out.</div>';
        btn.disabled=false;btn.textContent='Generate';
      }
    },3000);
  } catch(e){
    res.innerHTML='<div style="color:var(--red)">Error: '+e.message+'</div>';
    btn.disabled=false;btn.textContent='Generate';
  }
}

// Init
apiFetch('/admin/api/me').then(([,d])=>{
  document.getElementById('topUsername').textContent = d.username||'';
  allowedTypes = d.allowedTypes || ['all'];
  // Populate type selector
  const sel = document.getElementById('keyType');
  const visible = API_TYPES.filter(a => allowedTypes.includes('all') || allowedTypes.includes(a.type));
  sel.innerHTML = visible.map(a=>'<option value="'+a.type+'">'+a.icon+' '+a.label+'</option>').join('');
  // Endpoint ref
  const epRef = document.getElementById('epRef');
  epRef.innerHTML = visible.map(a=>\`<div class="ep-item">
    <span class="ep-method">GET</span><span class="ep-url">\${a.route}?\${a.paramName}=VALUE&apikey=YOUR_KEY</span>
    <div class="ep-prefix">Prefix: \${a.prefix}...</div>
  </div>\`).join('');
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
      return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
    } catch {}
  }
  res.send(loginHtml());
});

app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => res.send(superAdminDashboardHtml()));
app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.send(adminPanelHtml());
});

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (username === process.env.SUPER_ADMIN_USERNAME) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD) return res.status(401).json({ error: "Invalid credentials" });
    const sessionId = await createSession(username, req);
    const token = signToken({ username, role: "superadmin" }, sessionId);
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) return res.status(401).json({ error: "Invalid credentials" });
  const sessionId = await createSession(username, req);
  const token = signToken({ username, role: "admin" }, sessionId);
  res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
  return res.json({ success: true, role: "admin" });
});

app.post("/admin/logout", authMiddleware, async (req, res) => {
  if (req.user?.sessionId) await removeSession(req.user.sessionId);
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/admin/api/me", authMiddleware, async (req, res) => {
  if (isSuperAdmin(req.user.username)) {
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"] });
  }
  const admin = await Admin.findOne({ username: req.user.username });
  res.json({ username: req.user.username, role: "admin", allowedTypes: admin?.allowedTypes || ["all"] });
});

// ─────────────────────────────────────────────
// SESSION ROUTES
// ─────────────────────────────────────────────

// Clean expired sessions helper
async function cleanExpiredSessions() {
  await Session.deleteMany({ expiresAt: { $lt: new Date() } });
}

// My sessions
app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  await cleanExpiredSessions();
  const sessions = await Session.find({ username: req.user.username }).sort({ lastSeen: -1 }).lean();
  res.json({ sessions });
});

// All sessions (super admin)
app.get("/admin/api/sessions/all", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const sessions = await Session.find().sort({ username: 1, lastSeen: -1 }).lean();
  const byUser = {};
  for (const s of sessions) {
    if (!byUser[s.username]) byUser[s.username] = [];
    byUser[s.username].push(s);
  }
  res.json({ byUser, total: sessions.length });
});

// Revoke single session
app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const session = await Session.findById(req.params.id);
  if (!session) return res.status(404).json({ error: "Session not found" });
  // Admin can only revoke own sessions; superadmin can revoke any
  if (!isSuperAdmin(req.user.username) && session.username !== req.user.username) {
    return res.status(403).json({ error: "Forbidden" });
  }
  await Session.findByIdAndDelete(req.params.id);
  res.json({ message: "Session revoked" });
});

// Revoke all sessions for a user (super admin only)
app.delete("/admin/api/sessions/user/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (username === process.env.SUPER_ADMIN_USERNAME) return res.status(400).json({ error: "Cannot revoke superadmin sessions" });
  await Session.deleteMany({ username });
  res.json({ message: `All sessions revoked for ${username}` });
});

// ─────────────────────────────────────────────
// SUPER ADMIN API ROUTES
// ─────────────────────────────────────────────

app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const totalAdmins = await Admin.countDocuments();
  const totalKeys = await ApiKey.countDocuments();
  const activeKeys = await ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } });
  res.json({ totalAdmins, totalKeys, activeKeys });
});

app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const admins = await Admin.find({}, { password: 0 }).lean();
  const result = await Promise.all(admins.map(async (a) => ({
    ...a,
    keyCount: await ApiKey.countDocuments({ createdBy: a.username }),
    sessionCount: await Session.countDocuments({ username: a.username }),
  })));
  res.json({ admins: result });
});

app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password, allowedTypes = ["all"] } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (username === process.env.SUPER_ADMIN_USERNAME) return res.status(400).json({ error: "Reserved username" });
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(409).json({ error: "Admin already exists" });
  const hashed = await bcrypt.hash(password, 10);
  // Validate allowedTypes
  const validTypes = [...API_REGISTRY.map(a => a.type), "all"];
  const filteredTypes = allowedTypes.filter(t => validTypes.includes(t));
  await Admin.create({ username, password: hashed, allowedTypes: filteredTypes.length ? filteredTypes : ["all"] });
  res.status(201).json({ message: `Admin "${username}" created` });
});

app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (username === process.env.SUPER_ADMIN_USERNAME) return res.status(400).json({ error: "Cannot delete super admin" });
  const admin = await Admin.findOneAndDelete({ username });
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  await ApiKey.deleteMany({ createdBy: username });
  await Session.deleteMany({ username });
  res.json({ message: `Admin "${username}" deleted` });
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
  const keys = await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find((a) => a.type === keyType)) return res.status(400).json({ error: "Invalid key type" });

  // Check access permission
  if (!isSuperAdmin(req.user.username)) {
    const admin = await Admin.findOne({ username: req.user.username });
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType)) {
      return res.status(403).json({ error: `You don't have access to create ${keyType} keys` });
    }
  }

  const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000);
  const key = generateApiKey(keyType);
  await ApiKey.create({ key, label: label || "", createdBy: req.user.username, expiresAt, usageLimit: usageLimit > 0 ? usageLimit : null, keyType });
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

app.get("/generate/check", async (req, res) => {
  const { task_id } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!task_id) return res.status(400).json({ error: "task_id required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
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
    // Clean old sessions on startup
    await Session.deleteMany({ expiresAt: { $lt: new Date() } });
    app.listen(process.env.PORT || 3000, () => {
      console.log(`\n🚀 Server: http://localhost:${process.env.PORT || 3000}`);
      console.log(`🔐 Admin:  http://localhost:${process.env.PORT || 3000}/admin`);
      console.log(`\n📡 Public Endpoints:`);
      API_REGISTRY.forEach((a) => console.log(`   ${a.icon}  ${a.route}?${a.paramName}=VALUE&apikey=YOUR_KEY`));
      console.log("");
    });
  } catch (err) {
    console.error("❌ Startup error:", err.message);
    process.exit(1);
  }
}

start();
