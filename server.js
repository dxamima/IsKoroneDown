import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import bcrypt from "bcryptjs";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true if using HTTPS
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

const dbPromise = open({
  filename: "./reports.db",
  driver: sqlite3.Database
});

app.use(express.json());

// IP Blacklist and Maintenance Mode Middleware (must come before static files)
app.use(async (req, res, next) => {
  const db = await dbPromise;
  
  // Allow static assets during maintenance (images, CSS, JS, fonts)
  const isStaticAsset = /\.(png|jpg|jpeg|gif|svg|css|js|ttf|woff|woff2|ico)$/i.test(req.path);
  
  // Check maintenance mode (except for admin routes and static assets)
  if (!req.path.startsWith('/admin') && !isStaticAsset) {
    const maintenanceMode = await db.get("SELECT value FROM settings WHERE key = 'maintenance_mode'");
    if (maintenanceMode && maintenanceMode.value === 'true') {
      return res.sendFile(path.join(process.cwd(), 'public', 'maintenance.html'));
    }
  }
  
  // Check IP blacklist (except for admin routes and static assets during maintenance)
  const clientIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const blacklisted = await db.get("SELECT 1 FROM blacklisted_ips WHERE ip = ?", [clientIP]);
  if (blacklisted && !req.path.startsWith('/admin')) {
    return res.status(403).json({ error: "Access denied" });
  }
  
  next();
});

app.use(express.static("public"));

// Authentication middleware for admin routes
const requireAuth = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(401).json({ error: 'Authentication required' });
};

// Admin login route
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  // Verify credentials against environment variables
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Admin logout route
app.post('/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Admin panel main page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'admin.html'));
});

// Get admin dashboard data
app.get('/admin/dashboard', requireAuth, async (req, res) => {
  const db = await dbPromise;
  
  // Get all reporting IPs from last 24 hours
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const reports = await db.all(`
    SELECT ip, COUNT(*) as count, MAX(timestamp) as last_report 
    FROM reports 
    WHERE timestamp > ? 
    GROUP BY ip 
    ORDER BY count DESC
  `, [since]);
  
  // Get blacklisted IPs
  const blacklistedIPs = await db.all("SELECT * FROM blacklisted_ips ORDER BY timestamp DESC");
  
  // Get current settings
  const settings = await db.all("SELECT * FROM settings");
  const settingsObj = {};
  settings.forEach(setting => {
    settingsObj[setting.key] = setting.value;
  });
  
  res.json({
    reports,
    blacklistedIPs,
    settings: settingsObj
  });
});

// Set force status (up/down/auto)
app.post('/admin/set-status', requireAuth, async (req, res) => {
  const { status } = req.body;
  
  if (!['up', 'down', 'auto'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Must be up, down, or auto' });
  }
  
  const db = await dbPromise;
  await db.run("UPDATE settings SET value = ? WHERE key = 'force_status'", [status]);
  res.json({ success: true });
});

// Toggle maintenance mode
app.post('/admin/maintenance', requireAuth, async (req, res) => {
  const { enabled } = req.body;
  
  const db = await dbPromise;
  await db.run("UPDATE settings SET value = ? WHERE key = 'maintenance_mode'", [enabled ? 'true' : 'false']);
  res.json({ success: true });
});

// Blacklist an IP
app.post('/admin/blacklist', requireAuth, async (req, res) => {
  const { ip, reason } = req.body;
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  const db = await dbPromise;
  try {
    await db.run("INSERT INTO blacklisted_ips (ip, timestamp, reason) VALUES (?, ?, ?)", 
                 [ip, Date.now(), reason || 'No reason provided']);
    res.json({ success: true });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({ error: 'IP already blacklisted' });
    } else {
      res.status(500).json({ error: 'Database error' });
    }
  }
});

// Remove IP from blacklist
app.delete('/admin/blacklist/:ip', requireAuth, async (req, res) => {
  const { ip } = req.params;
  
  const db = await dbPromise;
  await db.run("DELETE FROM blacklisted_ips WHERE ip = ?", [ip]);
  res.json({ success: true });
});

(async () => {
  const db = await dbPromise;
  await db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      timestamp INTEGER
    )
  `);
  
  // Create blacklisted IPs table
  await db.run(`
    CREATE TABLE IF NOT EXISTS blacklisted_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT UNIQUE,
      timestamp INTEGER,
      reason TEXT
    )
  `);
  
  // Create settings table
  await db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);
  
  // Initialize default settings
  await db.run(`
    INSERT OR IGNORE INTO settings (key, value) VALUES 
    ('maintenance_mode', 'false'),
    ('force_status', 'auto')
  `);
})();

app.post("/report", async (req, res) => {
  const db = await dbPromise;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const now = Date.now();
  const since = now - 24 * 60 * 60 * 1000;
  const recent = await db.get(
    "SELECT 1 FROM reports WHERE ip = ? AND timestamp > ? LIMIT 1",
    [ip, since]
  );
  if (recent) {
    return res.status(429).json({ error: "You can only report once every 24 hours." });
  }
  await db.run("INSERT INTO reports (ip, timestamp) VALUES (?, ?)", [ip, now]);
  res.json({ success: true });
});

app.get("/status", async (req, res) => {
  const db = await dbPromise;
  
  // Check if status is forced
  const forceStatus = await db.get("SELECT value FROM settings WHERE key = 'force_status'");
  
  if (forceStatus && forceStatus.value !== 'auto') {
    const status = forceStatus.value === 'up' ? "Korone is up" : "Korone is probably down";
    return res.json({ status, count: 0, reports: [], forced: true });
  }
  
  // Normal logic
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const reports = await db.all("SELECT * FROM reports WHERE timestamp > ?", [since]);
  const count = reports.length;
  const status = count >= 30 ? "Korone is probably down" : "Korone is up";
  res.json({ status, count, reports, forced: false });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
