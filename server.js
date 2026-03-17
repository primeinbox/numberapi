require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { imgtotextai } = require('goodai');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// ─── API REGISTRY ───────────────────────────────────────────────────────────

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
  {
    type: "telegram",
    label: "Telegram Lookup",
    prefix: "tg_",
    route: "/tg",
    paramName: "userid",
    envKey: "UPSTREAM_TG_API_URL",
    description: "Telegram user ID lookup",
    icon: "✈️",
  },
];

// ─── SCHEMAS ─────────────────────────────────────────────────────────────────

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

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function generateApiKey(type) {
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
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
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

async function cleanExpiredSessions() {
  await Session.deleteMany({ expiresAt: { $lt: new Date() } });
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    if (req.user.sessionId) await touchSession(req.user.sessionId);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function superAdminOnly(req, res, next) {
  if (!req.user || !isSuperAdmin(req.user.username))
    return res.status(403).json({ error: "Super admin access required" });
  next();
}

async function validateApiKey(apiKey, requiredType) {
  const keyDoc = await ApiKey.findOne({ key: apiKey });
  if (!keyDoc) return { error: "Invalid API key", status: 401 };
  if (!keyDoc.isActive) return { error: "API key is disabled", status: 403 };
  if (keyDoc.keyType !== requiredType)
    return { error: "This key is not authorized for " + requiredType + " lookups", status: 403 };
  if (keyDoc.expiresAt < new Date()) return { error: "API key expired", status: 403 };
  if (keyDoc.usageLimit && keyDoc.usageCount >= keyDoc.usageLimit)
    return { error: "API key usage limit reached", status: 429 };
  return { keyDoc };
}

async function incrementUsage(keyId) {
  await ApiKey.findByIdAndUpdate(keyId, { $inc: { usageCount: 1 }, lastUsedAt: new Date() });
}

// ─── HTML ROUTES ─────────────────────────────────────────────────────────────

app.get("/admin", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    try {
      const user = jwt.verify(token, process.env.JWT_SECRET);
      return res.redirect(isSuperAdmin(user.username) ? "/admin/dashboard" : "/admin/panel");
    } catch {}
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/admin/dashboard", authMiddleware, superAdminOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "mainadmin.html"));
});

app.get("/admin/panel", authMiddleware, (req, res) => {
  if (isSuperAdmin(req.user.username)) return res.redirect("/admin/dashboard");
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// ─── AUTH API ────────────────────────────────────────────────────────────────

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  if (isSuperAdmin(username)) {
    if (password !== process.env.SUPER_ADMIN_PASSWORD)
      return res.status(401).json({ error: "Invalid credentials" });
    const sessionId = await createSession(username, req);
    const token = signToken({ username, role: "superadmin" }, sessionId);
    res.cookie("token", token, { httpOnly: true, maxAge: 8 * 3600 * 1000 });
    return res.json({ success: true, role: "superadmin" });
  }

  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password)))
    return res.status(401).json({ error: "Invalid credentials" });
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
  if (isSuperAdmin(req.user.username))
    return res.json({ username: req.user.username, role: "superadmin", allowedTypes: ["all"] });
  const admin = await Admin.findOne({ username: req.user.username });
  res.json({
    username: req.user.username,
    role: "admin",
    allowedTypes: admin?.allowedTypes || ["all"],
  });
});

// ─── CONFIG API (send API_REGISTRY to frontend) ───────────────────────────────

app.get("/admin/api/config", authMiddleware, (req, res) => {
  res.json({
    apiTypes: API_REGISTRY.map((a) => ({
      type: a.type,
      label: a.label,
      icon: a.icon,
      route: a.route,
      paramName: a.paramName,
      prefix: a.prefix,
    })),
  });
});

// ─── SESSION ROUTES ──────────────────────────────────────────────────────────

app.get("/admin/api/sessions/me", authMiddleware, async (req, res) => {
  await cleanExpiredSessions();
  const sessions = await Session.find({ username: req.user.username })
    .sort({ lastSeen: -1 })
    .lean();
  res.json({ sessions });
});

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

app.delete("/admin/api/sessions/:id", authMiddleware, async (req, res) => {
  const session = await Session.findById(req.params.id);
  if (!session) return res.status(404).json({ error: "Session not found" });
  if (!isSuperAdmin(req.user.username) && session.username !== req.user.username)
    return res.status(403).json({ error: "Forbidden" });
  await Session.findByIdAndDelete(req.params.id);
  res.json({ message: "Session revoked" });
});

app.delete("/admin/api/sessions/user/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot revoke superadmin sessions" });
  await Session.deleteMany({ username });
  res.json({ message: "All sessions revoked for " + username });
});

// ─── SUPER ADMIN API ─────────────────────────────────────────────────────────

app.get("/admin/api/stats", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const totalAdmins = await Admin.countDocuments();
  const totalKeys = await ApiKey.countDocuments();
  const activeKeys = await ApiKey.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } });
  const totalSessions = await Session.countDocuments();
  res.json({ totalAdmins, totalKeys, activeKeys, totalSessions });
});

app.get("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  await cleanExpiredSessions();
  const admins = await Admin.find({}, { password: 0 }).lean();
  const result = await Promise.all(
    admins.map(async (a) => ({
      ...a,
      keyCount: await ApiKey.countDocuments({ createdBy: a.username }),
      sessionCount: await Session.countDocuments({ username: a.username }),
    }))
  );
  res.json({ admins: result });
});

app.post("/admin/api/admins", authMiddleware, superAdminOnly, async (req, res) => {
  const { username, password, allowedTypes = ["all"] } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Reserved username" });
  const exists = await Admin.findOne({ username });
  if (exists) return res.status(409).json({ error: "Admin already exists" });
  const hashed = await bcrypt.hash(password, 10);
  const validTypes = [...API_REGISTRY.map((a) => a.type), "all"];
  const filtered = allowedTypes.filter((t) => validTypes.includes(t));
  await Admin.create({ username, password: hashed, allowedTypes: filtered.length ? filtered : ["all"] });
  res.status(201).json({ message: "Admin \"" + username + "\" created" });
});

app.delete("/admin/api/admins/:username", authMiddleware, superAdminOnly, async (req, res) => {
  const { username } = req.params;
  if (isSuperAdmin(username)) return res.status(400).json({ error: "Cannot delete super admin" });
  const admin = await Admin.findOneAndDelete({ username });
  if (!admin) return res.status(404).json({ error: "Admin not found" });
  await ApiKey.deleteMany({ createdBy: username });
  await Session.deleteMany({ username });
  res.json({ message: "Admin \"" + username + "\" deleted" });
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

// ─── ADMIN KEY ROUTES ─────────────────────────────────────────────────────────

app.get("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const keys = await ApiKey.find({ createdBy: req.user.username }).sort({ createdAt: -1 }).lean();
  res.json({ keys });
});

app.post("/admin/api/my-keys", authMiddleware, async (req, res) => {
  const { label, days = 7, usageLimit = 0, keyType = "number" } = req.body;
  if (!API_REGISTRY.find((a) => a.type === keyType))
    return res.status(400).json({ error: "Invalid key type" });

  if (!isSuperAdmin(req.user.username)) {
    const admin = await Admin.findOne({ username: req.user.username });
    const allowed = admin?.allowedTypes || ["all"];
    if (!allowed.includes("all") && !allowed.includes(keyType))
      return res.status(403).json({ error: "You don't have access to create " + keyType + " keys" });
  }

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

// ─── PUBLIC API ROUTES ────────────────────────────────────────────────────────

app.get("/lookup", async (req, res) => {
  const { number } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!number) return res.status(400).json({ error: "number query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "number");
  if (error) return res.status(status).json({ error });
  try {
    const response = await axios.get(process.env.UPSTREAM_API_URL + "?number=" + encodeURIComponent(number), { timeout: 10000 });
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
    const response = await axios.get(process.env.UPSTREAM_RTO_API_URL + "?rc=" + encodeURIComponent(rc), { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream RTO API error" });
  }
});

app.get("/tg", async (req, res) => {
  const { userid } = req.query;
  const apiKey = req.headers["x-api-key"] || req.query.apikey;
  if (!userid) return res.status(400).json({ error: "userid query param required" });
  if (!apiKey) return res.status(401).json({ error: "API key required" });
  const { error, status, keyDoc } = await validateApiKey(apiKey, "telegram");
  if (error) return res.status(status).json({ error });
  try {
    const url = `${process.env.UPSTREAM_TG_API_URL}?key=${process.env.TG_API_KEY}&type=tg&term=${encodeURIComponent(userid)}`;
    const response = await axios.get(url, { timeout: 10000 });
    await incrementUsage(keyDoc._id);
    const data = response.data;
    data.owner = "@aerivue";
    if (data.result && typeof data.result === "object") data.result.owner = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream Telegram API error" });
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
    const response = await axios.get(process.env.UPSTREAM_IMAGE_API_URL + "?prompt=" + encodeURIComponent(prompt), { timeout: 15000 });
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
    const response = await axios.get(process.env.UPSTREAM_IMAGE_CHECK_URL + "?task=" + encodeURIComponent(task_id), { timeout: 10000 });
    const data = response.data;
    data.credit = "@aerivue";
    return res.json(data);
  } catch (err) {
    if (err.response) return res.status(err.response.status).json(err.response.data);
    return res.status(500).json({ error: "Upstream check API error" });
  }
});

// ─── START ───────────────────────────────────────────────────────────────────

async function start() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
    await Session.deleteMany({ expiresAt: { $lt: new Date() } });
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log("Server: http://localhost:" + PORT);
      console.log("Admin:  http://localhost:" + PORT + "/admin");
    });
  } catch (err) {
    console.error("Startup error:", err.message);
    process.exit(1);
  }
}

start();
