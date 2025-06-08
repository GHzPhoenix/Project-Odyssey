
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();


const dbDir = path.join(__dirname, "../database");
const dbPath = path.join(dbDir, "travel_odyssey.db");

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}



const Database = require("better-sqlite3");
const db = new Database(dbPath, { timeout: 5000 });


console.log("✅ SQLite database opened at:", dbPath);


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
    CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    membership_type TEXT NOT NULL,
    membership_expires TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    deal_id INTEGER NOT NULL,
    destination TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    guests INTEGER NOT NULL CHECK(guests > 0),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(deal_id) REFERENCES deals(id)
  );

CREATE TABLE IF NOT EXISTS inquiries (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL,
  destination   TEXT NOT NULL,
  dates         TEXT NOT NULL,
  guests        INTEGER NOT NULL,
  budget        REAL    NOT NULL,
  preferences   TEXT,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
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

app.use(express.json({
  limit: "10mb" 
}));

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
    console.log("Register attempt:", { name, email }); 

    if (!name?.trim() || !email?.trim() || !password?.trim()) {
      console.log("Registration error: missing fields");
      return res.status(400).json({ error: "All fields required" });
    }
    if (password.length < 8) {
      console.log("Registration error: password too short");
      return res.status(400).json({ error: "Password must be 8+ characters" });
    }

    
    const existing = runAll("SELECT id FROM users WHERE email = ?", [email.trim()]);
    console.log("Existing lookup result:", existing);
    if (existing.length > 0) {
      console.log("Registration error: email already exists");
      return res.status(409).json({ error: "Email exists" });
    }

  
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed password:", hashedPassword);

    
    const info = runExec(
      `INSERT INTO users (name, email, password)
       VALUES (?, ?, ?)`,
      [name.trim(), email.trim(), hashedPassword]
    );
    console.log("Insert info:", info);

    const userId = info.lastInsertRowid;
    const user = runAll("SELECT id, name, email, role FROM users WHERE id = ?", [userId])[0];
    console.log("New user row:", user);

    return res.status(201).json(user);
  } catch (err) {
    console.error("Registration exception:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});
app.get("/api/membership", verifyToken, (req, res) => {
  try {
    const row = runAll(
      "SELECT membership_type, membership_expires FROM memberships WHERE user_id = ?",
      [req.userId]
    )[0];
    if (!row) {
      return res.status(404).json({ error: "No membership found" });
    }
    return res.json(row);
  } catch (err) {
    console.error("Fetch membership error:", err);
    return res.status(500).json({ error: "Failed to fetch membership" });
  }
});
app.post("/api/membership/renew", verifyToken, (req, res) => {
  try {

    const existing = runAll(
      "SELECT membership_type, membership_expires FROM memberships WHERE user_id = ?",
      [req.userId]
    )[0];

    const plan = existing?.membership_type || "Premium Plan";


    const now = new Date();
    let base = now;
    if (existing?.membership_expires) {
      const prev = new Date(existing.membership_expires);
      if (prev > now) base = prev;
    }
    const next = new Date(base);
    next.setFullYear(next.getFullYear() + 1);
    const isoDate = next.toISOString().split("T")[0]; 


    if (existing) {
      runExec(
        "UPDATE memberships SET membership_expires = ? WHERE user_id = ?",
        [isoDate, req.userId]
      );
    } else {
      runExec(
        "INSERT INTO memberships (user_id, membership_type, membership_expires) VALUES (?, ?, ?)",
        [req.userId, plan, isoDate]
      );
    }


    return res.json({
      membershipType: plan,
      expiresAt: isoDate
    });
  } catch (err) {
    console.error("Renew membership error:", err);
    return res.status(500).json({ error: "Renewal failed" });
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

    
    let validPassword;
    if (user.role === "admin") {
      validPassword = (password === user.password);
    } else {
      validPassword = await bcrypt.compare(password, user.password);
    }

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
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
app.get("/api/deals/:id", (req, res) => {
  try {
    const deal = runAll(
      "SELECT * FROM deals WHERE id = ?",
      [req.params.id]
    )[0];
    if (!deal) return res.status(404).json({ error: "Deal not found" });
    res.json(deal);
  } catch (err) {
    console.error("Fetch single deal error:", err);
    res.status(500).json({ error: "Failed to fetch deal" });
  }
});

app.post("/api/deals", verifyToken, verifyAdmin, (req, res) => {
  try {
    const {
      name,
      location,
      activities,
      start_date,
      end_date,
      image_url
    } = req.body;

    if (
      !name ||
      !location ||
      !activities ||
      !start_date ||
      !end_date ||
      !image_url
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const info = runExec(
      `INSERT INTO deals
         (name, location, activities, start_date, end_date, image_url)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, location, activities, start_date, end_date, image_url]
    );

    const dealId = info.lastInsertRowid;
    const newDeal = runAll("SELECT * FROM deals WHERE id = ?", [dealId])[0];
    return res.status(201).json(newDeal);
  } catch (err) {
    console.error("Create deal error:", err);
    return res.status(500).json({ error: "Failed to create deal" });
  }
});
app.post("/api/inquiries", (req, res) => {
  try {
    const { name, email, destination, dates, guests, budget, preferences } = req.body;
    if (!name || !email || !destination || !dates || !guests || !budget) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const info = runExec(
      `INSERT INTO inquiries 
         (name, email, destination, dates, guests, budget, preferences)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, email, destination, dates, guests, budget, preferences]
    );
    const inq = runAll("SELECT * FROM inquiries WHERE id = ?", [info.lastInsertRowid])[0];
    res.status(201).json(inq);
  } catch (err) {
    res.status(500).json({ error: "Failed to save inquiry" });
  }
});

app.get("/api/inquiries", verifyToken, verifyAdmin, (req, res) => {
  try {
    const list = runAll("SELECT * FROM inquiries ORDER BY created_at DESC");
    res.json(list);
  } catch {
    res.status(500).json({ error: "Failed to fetch inquiries" });
  }
});
app.get("/api/bookings", verifyToken, (req, res) => {
  try {
    const rows = runAll(
      `SELECT * FROM bookings WHERE user_id = ? ORDER BY id DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});
app.post("/api/bookings", verifyToken, (req, res) => {
  try {
    const { deal_id, destination, start_date, end_date, guests } = req.body;
    if (!deal_id || !destination || !start_date || !end_date || !guests) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const info = runExec(
      `INSERT INTO bookings
         (user_id, deal_id, destination, start_date, end_date, guests)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.userId, deal_id, destination, start_date, end_date, guests]
    );
    const booking = runAll(
      "SELECT * FROM bookings WHERE id = ?",
      [info.lastInsertRowid]
    )[0];
    res.status(201).json(booking);
  } catch (err) {
    console.error("Create booking error:", err);
    res.status(500).json({ error: "Failed to create booking" });
  }
});


console.log("🔍 About to start Express server on port", port);
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
