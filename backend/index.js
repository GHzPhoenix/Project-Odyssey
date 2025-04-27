const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();
const app = express();
const port = process.env.PORT || 5000;

// ✅ Manual CORS middleware (solves all issues)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://127.0.0.1:5500");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200); // ✅ Respond to preflight request
  }
  next();
});

// ✅ JSON parser
app.use(express.json());


// ✅ PostgreSQL Connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT || 5432,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL"))
  .catch((err) => console.error("❌ Database connection error:", err));

// ✅ Root test
app.get("/", (req, res) => {
  res.send("Travel Odyssey Backend is running ✅");
});

// 🔐 User Registration
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword]
    );
    res.status(201).json({ user: newUser.rows[0] });
  } catch (err) {
    console.error("🔥 REGISTRATION ERROR:", err);
    res.status(500).json({ error: "User registration failed" });
  }
});

// 🔐 User Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0) return res.status(401).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("🔥 LOGIN ERROR:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// 🔐 JWT Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 📅 Add Booking
app.post("/api/bookings", authenticateToken, async (req, res) => {
  const { destination, checkin_date, checkout_date, guests } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO bookings (user_id, destination, checkin_date, checkout_date, guests) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.id, destination, checkin_date, checkout_date, guests]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("🔥 BOOKING ERROR:", err);
    res.status(500).json({ error: "Booking failed" });
  }
});

// 📋 Get User Bookings
app.get("/api/bookings", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM bookings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("🔥 FETCH BOOKINGS ERROR:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// 🚀 Start Server
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
