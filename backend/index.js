const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

const corsOptions = {
  origin: "http://127.0.0.1:5500",
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));


app.use(express.json());


// ✅ JSON parser
app.use(express.json());

// ✅ PostgreSQL Connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT || 5432,
  ssl: false, // Local connection, no SSL needed
});

// ✅ Test database connection
pool.connect()
  .then(() => console.log("✅ Connected to PostgreSQL Database"))
  .catch((err) => console.error("❌ Database connection error:", err));

// ✅ Root Route
app.get("/", (req, res) => {
  res.send("🚀 Travel Odyssey Backend is Running!");
});

// 🔒 Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
}

// 📝 Register New User
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Please fill in all fields" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword]
    );

    res.status(201).json({ user: newUser.rows[0] });
  } catch (err) {
    console.error("🔥 Registration Error:", err);

    if (err.code === '23505') {
      // Duplicate email constraint violation
      return res.status(409).json({ error: "Email already registered" });
    }

    res.status(500).json({ error: "User registration failed" });
  }
});

// 🔑 Login User
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: "Please provide email and password" });
  }

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    console.error("🔥 Login Error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// 📅 Create Booking
app.post("/api/bookings", authenticateToken, async (req, res) => {
  const { destination, checkin_date, checkout_date, guests } = req.body;

  if (!destination || !checkin_date || !checkout_date || !guests) {
    return res.status(400).json({ error: "Please provide all booking details" });
  }

  try {
    const newBooking = await pool.query(
      "INSERT INTO bookings (user_id, destination, checkin_date, checkout_date, guests) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.id, destination, checkin_date, checkout_date, guests]
    );

    res.status(201).json(newBooking.rows[0]);
  } catch (err) {
    console.error("🔥 Booking Error:", err);
    res.status(500).json({ error: "Booking failed" });
  }
});

// 📋 Get User's Bookings
app.get("/api/bookings", authenticateToken, async (req, res) => {
  try {
    const bookings = await pool.query(
      "SELECT * FROM bookings WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );

    res.json(bookings.rows);
  } catch (err) {
    console.error("🔥 Fetch Bookings Error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// 🚀 Start Server
app.listen(port, () => {
  console.log(`🚀 Server running at: http://localhost:${port}`);
});
