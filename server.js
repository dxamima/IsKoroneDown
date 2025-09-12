import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";

const app = express();
const PORT = 3000;

const dbPromise = open({
  filename: "./reports.db",
  driver: sqlite3.Database
});

app.use(express.json());
app.use(express.static("public"));

(async () => {
  const db = await dbPromise;
  await db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT,
      timestamp INTEGER
    )
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
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const reports = await db.all("SELECT * FROM reports WHERE timestamp > ?", [since]);
  const count = reports.length;
  const status = count >= 30 ? "Korone is probably down" : "Korone is up";
  res.json({ status, count, reports });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
