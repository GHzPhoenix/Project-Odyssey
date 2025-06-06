// backend/index.js

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();


const dbDir = path.join(__dirname, "./database/travel_odyssey");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}


const dbPath = path.join(dbDir, "travel_odyssey.db");
const Database = require("better-sqlite3");
const db = new Database(dbPath, { timeout: 5000 });
//              └── waits up to 5000ms if the file is locked

console.log("✅ SQLite database opened at:", dbPath);

// 3) Ensure tables exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS deals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    rating REAL,
    description TEXT,
    price REAL NOT NULL CHECK(price >= 0),
    image_url TEXT NOT NULL,
    link TEXT NOT NULL,
    badge TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function runAll(sql, params = []) {
  return db.prepare(sql).all(...params);
}

function runExec(sql, params = []) {
  const stmt = db.prepare(sql);
  return stmt.run(...params);
}

const app = express();
const port = process.env.PORT || 5001;

const corsOptions = {
  origin: "http://127.0.0.1:5500",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(express.json());
app.use(cors(corsOptions));
app.options("*", (req, res) => {
  res.header("Access-Control-Allow-Origin", "http://127.0.0.1:5500");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.sendStatus(204);
});

app.get("/", (req, res) => {
  res.json({ status: "Server is running with SQLite" });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name?.trim() || !email?.trim() || !password?.trim()) {
      return res.status(400).json({ error: "All fields required" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be 8+ characters" });
    }

    const existing = runAll("SELECT id FROM users WHERE email = ?", [email.trim()]);
    if (existing.length > 0) {
      return res.status(409).json({ error: "Email exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const info = runExec(
      `INSERT INTO users (name, email, password)
       VALUES (?, ?, ?)`,
      [name.trim(), email.trim(), hashedPassword]
    );
    const userId = info.lastInsertRowid;
    const user = runAll("SELECT id, name, email FROM users WHERE id = ?", [userId])[0];
    res.status(201).json(user);
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email?.trim() || !password?.trim()) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const rows = runAll("SELECT * FROM users WHERE email = ?", [email.trim()]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    console.error("verifyToken error:", err);
    return res.status(403).json({ error: "Invalid token" });
  }
}

function verifyAdmin(req, res, next) {
  if (req.userRole !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

app.get("/api/deals", (req, res) => {
  try {
    const deals = runAll("SELECT * FROM deals ORDER BY id DESC");
    res.json(deals);
  } catch (err) {
    console.error("Fetch deals error:", err);
    res.status(500).json({ error: "Failed to fetch deals" });
  }
});

app.post("/api/deals", verifyToken, verifyAdmin, (req, res) => {
  try {
    const { title, rating, description, price, image_url, link, badge } = req.body;
    if (!title || price == null || !image_url || !link) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const info = runExec(
      `INSERT INTO deals (title, rating, description, price, image_url, link, badge)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, rating, description, price, image_url, link, badge]
    );
    const dealId = info.lastInsertRowid;
    const newDeal = runAll("SELECT * FROM deals WHERE id = ?", [dealId])[0];
    res.status(201).json(newDeal);
  } catch (err) {
    console.error("Create deal error:", err);
    res.status(500).json({ error: "Failed to create deal" });
  }
});

console.log("🔍 About to start Express server on port", port);
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
