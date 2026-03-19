const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { Pool } = require("pg");
const paypal = require("@paypal/checkout-server-sdk");
const Stripe = require("stripe");

// ─── DATABASE ──────────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS paypal_transactions (
      id TEXT PRIMARY KEY,
      reference_id TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      currency TEXT NOT NULL,
      create_time TEXT NOT NULL,
      user_email TEXT,
      deal_name TEXT
    );

    CREATE TABLE IF NOT EXISTS stripe_transactions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      plan_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      currency TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS deals (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      rating NUMERIC,
      description TEXT,
      price NUMERIC NOT NULL CHECK(price >= 0),
      image_url TEXT NOT NULL,
      link TEXT,
      badge TEXT,
      name TEXT,
      location TEXT,
      activities TEXT,
      start_date TEXT,
      end_date TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS memberships (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      membership_type TEXT NOT NULL,
      membership_expires TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      deal_id INTEGER NOT NULL,
      destination TEXT NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      guests INTEGER NOT NULL CHECK(guests > 0),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      cancelled_at TIMESTAMPTZ DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS inquiries (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      destination TEXT NOT NULL,
      dates TEXT NOT NULL,
      guests INTEGER NOT NULL,
      budget NUMERIC NOT NULL,
      preferences TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_preferences (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      travel_style TEXT,
      activities TEXT,
      cuisines TEXT,
      dietary_restrictions TEXT,
      budget_tier TEXT,
      companions TEXT,
      pace_preference TEXT,
      accommodation TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS generated_packages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      destination TEXT NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      duration INTEGER NOT NULL,
      guests INTEGER NOT NULL,
      price NUMERIC,
      itinerary TEXT,
      flight_info TEXT,
      hotel_info TEXT,
      status TEXT DEFAULT 'draft',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id),
      plan_id TEXT NOT NULL,
      billing_period TEXT NOT NULL DEFAULT 'monthly',
      status TEXT NOT NULL DEFAULT 'active',
      started_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TEXT
    );
  `);
  console.log("✅ PostgreSQL tables initialized");
}

// ─── EXPRESS SETUP ─────────────────────────────────────────────────────────────

const app = express();
const port = process.env.PORT || 5001;

// Raw body required for Stripe webhooks — must be before express.json()
app.use("/api/stripe/webhook", express.raw({ type: "application/json" }));
app.use(express.json({ limit: "10mb" }));
app.use(cors());

// ─── STRIPE ───────────────────────────────────────────────────────────────────

const stripe = process.env.STRIPE_SECRET_KEY
  ? Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const PLAN_PRICES = {
  explorer: { monthly: 2900,  yearly: 24900 },
  voyager:  { monthly: 5900,  yearly: 49900 },
  elite:    { monthly: 12900, yearly: 99900 },
};

// ─── PAYPAL ────────────────────────────────────────────────────────────────────

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET    = process.env.PAYPAL_SECRET;

function createPayPalClient() {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_SECRET) {
    throw new Error("PayPal credentials not configured");
  }
  const env =
    process.env.PAYPAL_ENV === "production"
      ? new paypal.core.LiveEnvironment(PAYPAL_CLIENT_ID, PAYPAL_SECRET)
      : new paypal.core.SandboxEnvironment(PAYPAL_CLIENT_ID, PAYPAL_SECRET);
  return new paypal.core.PayPalHttpClient(env);
}

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : null;

  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId   = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch {
    return res.status(403).json({ error: "Invalid token" });
  }
}

function verifyAdmin(req, res, next) {
  if (req.userRole !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

app.get("/", (req, res) => {
  res.json({ status: "Server is running with PostgreSQL" });
});

// ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password?.trim()) {
      return res.status(400).json({ error: "All fields required" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be 8+ characters" });
    }

    const existing = await query("SELECT id FROM users WHERE email = $1", [email.trim()]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Email exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email, role",
      [name.trim(), email.trim(), hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(201).json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email?.trim() || !password?.trim()) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const result = await query("SELECT * FROM users WHERE email = $1", [email.trim()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ error: "Server configuration error" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ─── USER PROFILE (self-update) ────────────────────────────────────────────────

app.put("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name?.trim() && !email?.trim()) {
      return res.status(400).json({ error: "At least one field required" });
    }

    const fields = [];
    const values = [];
    let idx = 1;

    if (name?.trim())  { fields.push(`name = $${idx++}`);  values.push(name.trim()); }
    if (email?.trim()) { fields.push(`email = $${idx++}`); values.push(email.trim()); }
    values.push(req.userId);

    const result = await query(
      `UPDATE users SET ${fields.join(", ")} WHERE id = $${idx} RETURNING id, name, email, role`,
      values
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// ─── ADMIN USER ROUTES ─────────────────────────────────────────────────────────

app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT u.id, u.name, u.email, u.role, u.created_at,
             m.membership_expires AS "membershipExpires"
      FROM users u
      LEFT JOIN memberships m ON m.user_id = u.id
      ORDER BY u.id
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get("/api/users/summary", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const r = await query(`
      SELECT
        COUNT(*) AS total_users,
        SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS total_admins,
        SUM(CASE WHEN role = 'user'  THEN 1 ELSE 0 END) AS total_standard
      FROM users
    `);
    res.json(r.rows[0]);
  } catch (err) {
    console.error("Fetch user summary error:", err);
    res.status(500).json({ error: "Failed to fetch user summary" });
  }
});

app.get("/api/users/all", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(
      "SELECT id, name, email, role, created_at FROM users ORDER BY id"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch all users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.put("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, email, role } = req.body;

    if (!name || !email || !role) {
      return res.status(400).json({ error: "Name, email and role are required" });
    }
    if (id === req.userId && role !== req.userRole) {
      return res.status(403).json({ error: "Cannot change your own role" });
    }

    const result = await query(
      "UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4 RETURNING id, name, email, role",
      [name.trim(), email.trim(), role, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

app.delete("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid user ID" });
    if (id === req.userId) {
      return res.status(403).json({ error: "Cannot delete your own account" });
    }
    await query("DELETE FROM users WHERE id = $1", [id]);
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// ─── MEMBERSHIP ROUTES ─────────────────────────────────────────────────────────

app.get("/api/membership", verifyToken, async (req, res) => {
  try {
    const result = await query(
      "SELECT membership_type, membership_expires FROM memberships WHERE user_id = $1",
      [req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No membership found" });
    }
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Fetch membership error:", err);
    return res.status(500).json({ error: "Failed to fetch membership" });
  }
});

app.post("/api/membership/renew", verifyToken, async (req, res) => {
  try {
    const existing = await query(
      "SELECT membership_type, membership_expires FROM memberships WHERE user_id = $1",
      [req.userId]
    );
    const row  = existing.rows[0];
    const plan = row?.membership_type || "Premium Plan";

    const now  = new Date();
    let base   = now;
    if (row?.membership_expires) {
      const prev = new Date(row.membership_expires);
      if (prev > now) base = prev;
    }
    const next    = new Date(base);
    next.setFullYear(next.getFullYear() + 1);
    const isoDate = next.toISOString().split("T")[0];

    if (row) {
      await query(
        "UPDATE memberships SET membership_expires = $1 WHERE user_id = $2",
        [isoDate, req.userId]
      );
    } else {
      await query(
        "INSERT INTO memberships (user_id, membership_type, membership_expires) VALUES ($1, $2, $3)",
        [req.userId, plan, isoDate]
      );
    }
    return res.json({ membershipType: plan, expiresAt: isoDate });
  } catch (err) {
    console.error("Renew membership error:", err);
    return res.status(500).json({ error: "Renewal failed" });
  }
});

app.post("/api/membership/purchase", verifyToken, async (req, res) => {
  try {
    const planId   = "Premium";
    const existing = await query(
      "SELECT membership_expires FROM memberships WHERE user_id = $1",
      [req.userId]
    );
    const row = existing.rows[0];

    let base = new Date();
    if (row && new Date(row.membership_expires) > base) {
      base = new Date(row.membership_expires);
    }
    const next    = new Date(base);
    next.setFullYear(next.getFullYear() + 1);
    const isoDate = next.toISOString().split("T")[0];

    await query(
      `INSERT INTO memberships (user_id, membership_type, membership_expires)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET
         membership_type     = EXCLUDED.membership_type,
         membership_expires  = EXCLUDED.membership_expires`,
      [req.userId, planId, isoDate]
    );

    const updated = await query(
      `SELECT membership_type AS "membershipType", membership_expires AS "membershipExpires"
       FROM memberships WHERE user_id = $1`,
      [req.userId]
    );
    res.json(updated.rows[0]);
  } catch (err) {
    console.error("Purchase membership error:", err);
    res.status(500).json({ error: "Purchase failed" });
  }
});

// ─── DEALS ROUTES ──────────────────────────────────────────────────────────────

app.get("/api/deals", async (req, res) => {
  try {
    const result = await query("SELECT * FROM deals ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch deals error:", err);
    res.status(500).json({ error: "Failed to fetch deals" });
  }
});

app.get("/api/deals/:id", async (req, res) => {
  try {
    const result = await query("SELECT * FROM deals WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Deal not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Fetch single deal error:", err);
    res.status(500).json({ error: "Failed to fetch deal" });
  }
});

app.post("/api/deals", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const {
      title, name, location, activities, start_date, end_date,
      image_url, price, description, rating, badge, link,
    } = req.body;
    const dealTitle = title || name;

    if (!dealTitle || !image_url || price == null) {
      return res.status(400).json({ error: "Missing required fields: title/name, image_url, and price are required" });
    }
    const p = parseFloat(price);
    if (isNaN(p) || p < 0) return res.status(400).json({ error: "Invalid price" });

    const result = await query(
      `INSERT INTO deals
         (title, name, location, activities, start_date, end_date, image_url, price, description, rating, badge, link)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [dealTitle, name, location, activities, start_date, end_date, image_url, p, description, rating, badge, link]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create deal error:", err);
    return res.status(500).json({ error: "Failed to create deal" });
  }
});

app.put("/api/deals/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const {
      title, name, location, activities, start_date, end_date,
      price, description, rating, badge, link,
    } = req.body;
    const dealTitle = title || name;

    if (!dealTitle || price == null) {
      return res.status(400).json({ error: "Title/name and price are required" });
    }
    const p = parseFloat(price);
    if (isNaN(p) || p < 0) return res.status(400).json({ error: "Invalid price" });

    const result = await query(
      `UPDATE deals
       SET title=$1, name=$2, location=$3, activities=$4, start_date=$5, end_date=$6,
           price=$7, description=$8, rating=$9, badge=$10, link=$11
       WHERE id=$12 RETURNING *`,
      [dealTitle, name, location, activities, start_date, end_date, p, description, rating, badge, link, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update deal error:", err);
    res.status(500).json({ error: "Failed to update deal" });
  }
});

// ─── BOOKING ROUTES ────────────────────────────────────────────────────────────

app.get("/api/bookings/all", verifyToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT
        COUNT(*) AS total_bookings,
        SUM(guests) AS total_guests,
        SUM(CASE WHEN cancelled_at IS NULL     THEN 1 ELSE 0 END) AS active_bookings,
        SUM(CASE WHEN cancelled_at IS NOT NULL THEN 1 ELSE 0 END) AS cancelled_bookings
      FROM bookings
    `);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Fetch booking stats error:", err);
    res.status(500).json({ error: "Failed to fetch booking data" });
  }
});

app.get("/api/bookings/summary", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT
        COUNT(*) AS total_bookings,
        COALESCE(SUM(guests), 0) AS total_guests,
        SUM(CASE WHEN cancelled_at IS NULL     THEN 1 ELSE 0 END) AS active_bookings,
        SUM(CASE WHEN cancelled_at IS NOT NULL THEN 1 ELSE 0 END) AS cancelled_bookings
      FROM bookings
    `);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Fetch bookings summary error:", err);
    res.status(500).json({ error: "Failed to fetch bookings summary" });
  }
});

app.get("/api/bookings/active", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT id, user_id, deal_id, destination, start_date, end_date, guests, created_at
      FROM bookings WHERE cancelled_at IS NULL ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch active bookings error:", err);
    res.status(500).json({ error: "Failed to fetch active bookings" });
  }
});

app.get("/api/bookings/cancelled", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT id, destination, start_date, end_date, guests, cancelled_at
      FROM bookings WHERE cancelled_at IS NOT NULL ORDER BY cancelled_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch cancelled bookings" });
  }
});

app.get("/api/bookings", verifyToken, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, deal_id, destination, start_date, end_date, guests
       FROM bookings WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

app.post("/api/bookings", verifyToken, async (req, res) => {
  try {
    const { deal_id, destination, start_date, end_date, guests } = req.body;
    if (!deal_id || !destination || !start_date || !end_date || !guests || guests < 1) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const result = await query(
      `INSERT INTO bookings (user_id, deal_id, destination, start_date, end_date, guests)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, deal_id, destination, start_date, end_date, guests`,
      [req.userId, deal_id, destination, start_date, end_date, guests]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create booking error:", err);
    return res.status(500).json({ error: "Failed to create booking" });
  }
});

app.patch("/api/bookings/:id/cancel", verifyToken, async (req, res) => {
  const bookingId = Number(req.params.id);
  if (isNaN(bookingId)) return res.status(400).json({ error: "Invalid booking ID" });

  try {
    const result = await query(
      "SELECT user_id, cancelled_at FROM bookings WHERE id = $1",
      [bookingId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Booking not found" });

    const booking = result.rows[0];
    if (booking.user_id !== req.userId && req.userRole !== "admin") {
      return res.status(403).json({ error: "Not authorized to cancel this booking" });
    }
    if (booking.cancelled_at) {
      return res.status(400).json({ error: "Booking already cancelled" });
    }

    const now = new Date().toISOString();
    await query("UPDATE bookings SET cancelled_at = $1 WHERE id = $2", [now, bookingId]);
    res.json({ message: "Booking cancelled", cancelled_at: now });
  } catch (err) {
    console.error("Cancel booking error:", err);
    res.status(500).json({ error: "Failed to cancel booking" });
  }
});

app.delete("/api/bookings/:id", verifyToken, async (req, res) => {
  const bookingId = Number(req.params.id);
  if (isNaN(bookingId)) return res.status(400).json({ error: "Invalid booking ID" });

  try {
    const result = await query("SELECT user_id FROM bookings WHERE id = $1", [bookingId]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Booking not found" });

    const { user_id } = result.rows[0];
    if (user_id !== req.userId && req.userRole !== "admin") {
      return res.status(403).json({ error: "Not authorized to delete this booking" });
    }
    await query("DELETE FROM bookings WHERE id = $1", [bookingId]);
    res.json({ message: "Booking deleted" });
  } catch (err) {
    console.error("Delete booking error:", err);
    res.status(500).json({ error: "Failed to delete booking" });
  }
});

// ─── INQUIRY ROUTES ────────────────────────────────────────────────────────────

app.post("/api/inquiries", async (req, res) => {
  try {
    const { name, email, destination, dates, guests, budget, preferences } = req.body;
    if (!name || !email || !destination || !dates || !guests || !budget) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const result = await query(
      `INSERT INTO inquiries (name, email, destination, dates, guests, budget, preferences)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [name, email, destination, dates, guests, budget, preferences]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create inquiry error:", err);
    res.status(500).json({ error: "Failed to save inquiry" });
  }
});

app.get("/api/inquiries", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query("SELECT * FROM inquiries ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch inquiries error:", err);
    res.status(500).json({ error: "Failed to fetch inquiries" });
  }
});

// ─── PAYPAL ROUTES ─────────────────────────────────────────────────────────────

app.get("/api/config/paypal", (req, res) => {
  res.json({ clientId: PAYPAL_CLIENT_ID });
});

app.post("/api/paypal/order", verifyToken, async (req, res) => {
  try {
    const { planId } = req.body;
    const amount     = planId === "premium" ? "99.00" : "49.00";

    const ppClient = createPayPalClient();
    const request  = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [{ reference_id: planId, amount: { currency_code: "EUR", value: amount } }],
    });

    const order = await ppClient.execute(request);
    res.json({
      orderID:     order.result.id,
      approveLink: order.result.links.find((l) => l.rel === "approve").href,
    });
  } catch (err) {
    console.error("PayPal create order error:", err);
    res.status(500).json({ error: "Could not create PayPal order" });
  }
});

app.post("/api/paypal/capture/:orderID", verifyToken, async (req, res) => {
  const { orderID } = req.params;
  try {
    const ppClient = createPayPalClient();
    const request  = new paypal.orders.OrdersCaptureRequest(orderID);
    request.requestBody({});

    const captureResponse = await ppClient.execute(request);
    const pu  = captureResponse.result.purchase_units[0];
    const cap = pu.payments.captures[0];

    const userResult = await query("SELECT email FROM users WHERE id = $1", [req.userId]);
    const userEmail  = userResult.rows[0]?.email || null;

    let dealName = null;
    if (/^\d+$/.test(pu.reference_id)) {
      const dealResult = await query("SELECT name FROM deals WHERE id = $1", [pu.reference_id]);
      dealName = dealResult.rows[0]?.name || null;
    }

    await query(
      `INSERT INTO paypal_transactions (id, reference_id, amount, currency, create_time, user_email, deal_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
      [cap.id, pu.reference_id, parseFloat(cap.amount.value), cap.amount.currency_code, cap.create_time, userEmail, dealName]
    );

    return res.json({ capture: captureResponse.result });
  } catch (err) {
    const isAlreadyCaptured =
      err.statusCode === 422 && err._originalError?.text?.includes("ORDER_ALREADY_CAPTURED");

    if (isAlreadyCaptured) {
      try {
        const ppClient  = createPayPalClient();
        const getRequest = new paypal.orders.OrdersGetRequest(orderID);
        const details   = await ppClient.execute(getRequest);
        return res.json({ capture: details.result });
      } catch (getErr) {
        console.error("Failed to GET already-captured order:", getErr);
        return res.status(500).json({ error: "Could not retrieve captured order details" });
      }
    }

    console.error("PayPal capture error:", err);
    return res.status(500).json({ error: "Could not capture PayPal order" });
  }
});

app.get("/api/paypal/transactions", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT id, reference_id, deal_name, user_email, amount, currency, create_time
      FROM paypal_transactions ORDER BY create_time DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Fetch transactions error:", err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// ─── STRIPE ROUTES ─────────────────────────────────────────────────────────────

app.get("/api/config/stripe", (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || null });
});

app.post("/api/stripe/create-payment-intent", verifyToken, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(503).json({ error: "Stripe not configured" });
    }
    const { planId, billingPeriod = "monthly" } = req.body;
    const planPrices = PLAN_PRICES[planId];
    if (!planPrices) {
      return res.status(400).json({ error: "Invalid plan" });
    }

    const amount     = billingPeriod === "yearly" ? planPrices.yearly : planPrices.monthly;
    const userResult = await query("SELECT email FROM users WHERE id = $1", [req.userId]);
    const userEmail  = userResult.rows[0]?.email;

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: "eur",
      receipt_email: userEmail,
      metadata: { userId: req.userId.toString(), planId, billingPeriod },
    });

    res.json({ clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id });
  } catch (err) {
    console.error("Stripe payment intent error:", err);
    res.status(500).json({ error: "Failed to create payment intent" });
  }
});

app.post("/api/stripe/webhook", async (req, res) => {
  if (!stripe) return res.sendStatus(400);

  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Stripe webhook signature error:", err.message);
    return res.status(400).json({ error: `Webhook error: ${err.message}` });
  }

  if (event.type === "payment_intent.succeeded") {
    const pi = event.data.object;
    const { userId, planId, billingPeriod } = pi.metadata;

    try {
      await query(
        `INSERT INTO stripe_transactions (id, user_id, plan_id, amount, currency, status)
         VALUES ($1,$2,$3,$4,$5,'succeeded') ON CONFLICT (id) DO NOTHING`,
        [pi.id, parseInt(userId), planId, pi.amount, pi.currency]
      );

      const expiresAt = new Date();
      if (billingPeriod === "yearly") {
        expiresAt.setFullYear(expiresAt.getFullYear() + 1);
      } else {
        expiresAt.setMonth(expiresAt.getMonth() + 1);
      }

      await query(
        `INSERT INTO subscriptions (user_id, plan_id, billing_period, status, expires_at)
         VALUES ($1,$2,$3,'active',$4)
         ON CONFLICT (user_id) DO UPDATE SET
           plan_id        = EXCLUDED.plan_id,
           billing_period = EXCLUDED.billing_period,
           status         = 'active',
           expires_at     = EXCLUDED.expires_at`,
        [parseInt(userId), planId, billingPeriod, expiresAt.toISOString()]
      );

      await query(
        `INSERT INTO memberships (user_id, membership_type, membership_expires)
         VALUES ($1,$2,$3)
         ON CONFLICT (user_id) DO UPDATE SET
           membership_type    = EXCLUDED.membership_type,
           membership_expires = EXCLUDED.membership_expires`,
        [parseInt(userId), planId, expiresAt.toISOString()]
      );
    } catch (dbErr) {
      console.error("Stripe webhook DB error:", dbErr);
    }
  }

  res.sendStatus(200);
});

// ─── USER PREFERENCES ─────────────────────────────────────────────────────────

app.post("/api/preferences", verifyToken, async (req, res) => {
  try {
    const {
      travelStyle, activities, cuisines, dietaryRestrictions,
      budgetTier, companions, pacePreference, accommodation,
    } = req.body;

    await query(
      `INSERT INTO user_preferences
         (user_id, travel_style, activities, cuisines, dietary_restrictions,
          budget_tier, companions, pace_preference, accommodation)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (user_id) DO UPDATE SET
         travel_style          = EXCLUDED.travel_style,
         activities            = EXCLUDED.activities,
         cuisines              = EXCLUDED.cuisines,
         dietary_restrictions  = EXCLUDED.dietary_restrictions,
         budget_tier           = EXCLUDED.budget_tier,
         companions            = EXCLUDED.companions,
         pace_preference       = EXCLUDED.pace_preference,
         accommodation         = EXCLUDED.accommodation,
         updated_at            = NOW()`,
      [
        req.userId,
        travelStyle || null,
        JSON.stringify(activities || []),
        JSON.stringify(cuisines || []),
        JSON.stringify(dietaryRestrictions || []),
        budgetTier || null,
        companions || null,
        pacePreference || null,
        accommodation || null,
      ]
    );
    res.json({ success: true, message: "Preferences saved" });
  } catch (err) {
    console.error("Save preferences error:", err);
    res.status(500).json({ error: "Failed to save preferences" });
  }
});

app.get("/api/preferences", verifyToken, async (req, res) => {
  try {
    const result = await query(
      "SELECT * FROM user_preferences WHERE user_id = $1",
      [req.userId]
    );
    if (result.rows.length === 0) return res.json(null);

    const prefs = result.rows[0];
    res.json({
      travelStyle:          prefs.travel_style,
      activities:           JSON.parse(prefs.activities || "[]"),
      cuisines:             JSON.parse(prefs.cuisines || "[]"),
      dietaryRestrictions:  JSON.parse(prefs.dietary_restrictions || "[]"),
      budgetTier:           prefs.budget_tier,
      companions:           prefs.companions,
      pacePreference:       prefs.pace_preference,
      accommodation:        prefs.accommodation,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch preferences" });
  }
});

// ─── AI PACKAGE GENERATION ────────────────────────────────────────────────────

app.post("/api/packages/generate", verifyToken, async (req, res) => {
  const { destination, startDate, endDate, guests } = req.body;

  if (!destination || !startDate || !endDate) {
    return res.status(400).json({ error: "destination, startDate, and endDate are required" });
  }

  try {
    const prefsResult = await query(
      "SELECT * FROM user_preferences WHERE user_id = $1",
      [req.userId]
    );
    const userResult = await query("SELECT name, email FROM users WHERE id = $1", [req.userId]);
    const userInfo = userResult.rows[0] || {};
    const prefs   = prefsResult.rows[0] || null;
    const startDt = new Date(startDate);
    const endDt   = new Date(endDate);
    const duration = Math.ceil((endDt - startDt) / (1000 * 60 * 60 * 24));

    // ── Save request as pending ──────────────────────────────────────────────
    const reqResult = await query(
      `INSERT INTO generated_packages
         (user_id, destination, start_date, end_date, duration, guests, price, itinerary, flight_info, hotel_info, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending') RETURNING id`,
      [req.userId, destination, startDate, endDate, duration, guests || 1, 0, '[]', '{}', '{}']
    );
    const requestId = reqResult.rows[0].id;

    // ── Send email notification to admin ─────────────────────────────────────
    if (process.env.RESEND_API_KEY) {
      try {
        const { Resend } = require("resend");
        const resend = new Resend(process.env.RESEND_API_KEY);
        const formatDate = (d) => {
          const dt = new Date(d);
          return `${String(dt.getDate()).padStart(2,'0')}/${String(dt.getMonth()+1).padStart(2,'0')}/${dt.getFullYear()}`;
        };
        await resend.emails.send({
          from: "Travel Odyssey <onboarding@resend.dev>",
          to: "pavlos_ant_@hotmail.com",
          subject: `✈️ New Trip Request #${requestId} — ${destination}`,
          html: `
            <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0A0A0F;color:#fff;padding:32px;border-radius:12px;">
              <h1 style="color:#C9A84C;margin-bottom:4px;">New Trip Request</h1>
              <p style="color:#888;margin-top:0;">Request #${requestId}</p>
              <hr style="border-color:#222;margin:24px 0;"/>
              <table style="width:100%;border-collapse:collapse;">
                <tr><td style="padding:8px 0;color:#888;width:140px;">👤 Customer</td><td style="color:#fff;font-weight:600;">${userInfo.name || 'Unknown'} (${userInfo.email || 'Unknown'})</td></tr>
                <tr><td style="padding:8px 0;color:#888;">📍 Destination</td><td style="color:#fff;font-weight:600;">${destination}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">📅 Departure</td><td style="color:#fff;font-weight:600;">${formatDate(startDate)}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">📅 Return</td><td style="color:#fff;font-weight:600;">${formatDate(endDate)}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">⏱ Duration</td><td style="color:#fff;font-weight:600;">${duration} days</td></tr>
                <tr><td style="padding:8px 0;color:#888;">👥 Guests</td><td style="color:#fff;font-weight:600;">${guests || 1}</td></tr>
                ${prefs ? `
                <tr><td style="padding:8px 0;color:#888;">🎒 Travel Style</td><td style="color:#fff;">${prefs.travel_style || '—'}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">💰 Budget Tier</td><td style="color:#fff;">${prefs.budget_tier || '—'}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">🍽 Cuisines</td><td style="color:#fff;">${JSON.parse(prefs.cuisines || '[]').join(', ') || '—'}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">🏃 Activities</td><td style="color:#fff;">${JSON.parse(prefs.activities || '[]').join(', ') || '—'}</td></tr>
                <tr><td style="padding:8px 0;color:#888;">👫 Companions</td><td style="color:#fff;">${prefs.companions || '—'}</td></tr>
                ` : '<tr><td colspan="2" style="color:#888;padding:8px 0;">No preferences saved</td></tr>'}
              </table>
              <hr style="border-color:#222;margin:24px 0;"/>
              <p style="color:#888;font-size:13px;">Reply to <strong style="color:#fff;">${userInfo.email}</strong> with the crafted package.</p>
            </div>
          `,
        });
      } catch (emailErr) {
        console.error("Email send error:", emailErr.message);
      }
    }

    // ── Return confirmation to user ──────────────────────────────────────────
    return res.json({
      status: "pending",
      requestId,
      message: "Your trip request has been received! Our travel experts will craft your personalised package and get back to you within 24 hours.",
    });

  } catch (err) {
    console.error("Package request error:", err);
    res.status(500).json({ error: "Failed to submit request" });
  }
});

app.post("/api/packages/generate-ai", verifyToken, async (req, res) => {
  const { destination, startDate, endDate, guests } = req.body;

  if (!destination || !startDate || !endDate) {
    return res.status(400).json({ error: "destination, startDate, and endDate are required" });
  }

  try {
    const prefsResult = await query(
      "SELECT * FROM user_preferences WHERE user_id = $1",
      [req.userId]
    );
    const prefs   = prefsResult.rows[0] || null;
    const startDt = new Date(startDate);
    const endDt   = new Date(endDate);
    const duration = Math.ceil((endDt - startDt) / (1000 * 60 * 60 * 24));

    const preferenceContext = prefs ? `
      Travel style: ${prefs.travel_style || "flexible"}
      Activities: ${prefs.activities || "[]"}
      Cuisines: ${JSON.parse(prefs.cuisines || "[]").join(", ") || "any"}
      Dietary restrictions: ${JSON.parse(prefs.dietary_restrictions || "[]").join(", ") || "none"}
      Budget tier: ${prefs.budget_tier || "moderate"}
      Traveling with: ${prefs.companions || "partner"}
    ` : "No specific preferences set.";

    let itinerary = [];
    let flightInfo = null;
    let hotelInfo  = null;
    let price = 0;

    if (process.env.ANTHROPIC_API_KEY) {
      const Anthropic = require("@anthropic-ai/sdk");
      const client    = new Anthropic();

      const prompt = `You are a luxury travel concierge. Create a detailed ${duration}-day travel package to ${destination} for ${guests} guest(s).

User preferences:
${preferenceContext}

Travel dates: ${startDate} to ${endDate}

Generate a complete JSON package with:
1. A day-by-day itinerary (array of objects with: day, date, title, description, activities[], meals[])
2. Flight info (outbound and return flight details)
3. Hotel recommendation
4. Total price estimate in EUR per person

Each meal should include: type (breakfast/lunch/dinner), restaurant name, cuisine, description, priceRange
Each activity should include: name, type, duration, description, icon (Ionicons name)

Respond ONLY with valid JSON in this format:
{
  "itinerary": [...],
  "flight": { "outbound": {...}, "return": {...}, "class": "Economy" },
  "hotel": { "name": "...", "stars": 4, "location": "...", "description": "...", "amenities": [...] },
  "price": 2500,
  "summary": "One sentence description of the trip"
}`;

      try {
        const message = await client.messages.create({
          model: "claude-sonnet-4-6",
          max_tokens: 4096,
          messages: [{ role: "user", content: prompt }],
        });
        const content   = message.content[0].type === "text" ? message.content[0].text : "";
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          itinerary = parsed.itinerary || [];
          flightInfo = parsed.flight || null;
          hotelInfo  = parsed.hotel  || null;
          price      = parsed.price  || 0;
        }
      } catch (aiErr) {
        console.error("AI generation error:", aiErr.message);
      }
    }

    // Fallback mock generation
    if (itinerary.length === 0) {
      price =
        prefs?.budget_tier === "luxury"  ? 5500 :
        prefs?.budget_tier === "premium" ? 3500 :
        prefs?.budget_tier === "budget"  ? 1200 : 2200;

      itinerary = Array.from({ length: Math.min(duration, 7) }, (_, i) => {
        const d = new Date(startDt);
        d.setDate(d.getDate() + i);
        return {
          day:  i + 1,
          date: d.toISOString().split("T")[0],
          title:       `Day ${i + 1} in ${destination}`,
          description: `Explore ${destination} with curated experiences`,
          activities: [
            { name: "Morning walk",       type: "leisure", duration: "1h",   description: "Start your day exploring the city", icon: "walk" },
            { name: "Local lunch",        type: "food",    duration: "1.5h", description: "Authentic local cuisine",           icon: "restaurant" },
            { name: "Evening experience", type: "culture", duration: "2h",   description: "Curated evening activity",           icon: "ticket" },
          ],
          meals: [
            { type: "breakfast", restaurant: "Hotel Restaurant",       cuisine: "Continental", description: "Hotel breakfast",     priceRange: "€€" },
            { type: "lunch",     restaurant: "Local Bistro",           cuisine: "Local",       description: "Authentic local food", priceRange: "€€" },
            { type: "dinner",    restaurant: "Recommended Restaurant", cuisine: "Fine Dining", description: "Evening dining",       priceRange: "€€€" },
          ],
        };
      });

      flightInfo = {
        outbound: { airline: "Air France", flightNumber: "AF123", departure: "09:00", arrival: "13:00", duration: "3h", stops: 0 },
        return:   { airline: "Air France", flightNumber: "AF456", departure: "16:00", arrival: "20:00", duration: "3h", stops: 0 },
        class:    "Economy",
      };

      hotelInfo = {
        name:        `${destination} Boutique Hotel`,
        stars:       prefs?.budget_tier === "luxury" ? 5 : 4,
        location:    `Central ${destination}`,
        description: `A carefully selected hotel in the heart of ${destination}`,
        amenities:   ["WiFi", "Breakfast", "Gym", "Concierge"],
      };
    }

    const result = await query(
      `INSERT INTO generated_packages
         (user_id, destination, start_date, end_date, duration, guests, price, itinerary, flight_info, hotel_info, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'generated') RETURNING id`,
      [
        req.userId, destination, startDate, endDate, duration, guests || 1, price,
        JSON.stringify(itinerary), JSON.stringify(flightInfo), JSON.stringify(hotelInfo),
      ]
    );

    const packageId = result.rows[0].id.toString();

    res.json({
      package: {
        id: packageId,
        destination,
        country: destination,
        startDate,
        endDate,
        duration,
        price,
        rating:       4.8,
        reviewCount:  0,
        isAIGenerated: true,
        badge:        "AI Curated",
        summary:      `A personalized ${duration}-day ${destination} experience crafted for you`,
        itinerary,
        flight:       flightInfo,
        hotel:        hotelInfo,
        included:     ["Flights", "Hotel", "Restaurant Reservations", "Experience Tickets"],
        highlights:   [`${duration} days in ${destination}`, "Curated for your preferences", "AI-powered itinerary"],
      },
    });
  } catch (err) {
    console.error("Package generation error:", err);
    res.status(500).json({ error: "Failed to generate package" });
  }
});

app.get("/api/packages/:id", verifyToken, async (req, res) => {
  try {
    const result = await query(
      "SELECT * FROM generated_packages WHERE id = $1",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Package not found" });

    const pkg = result.rows[0];
    res.json({
      ...pkg,
      itinerary: JSON.parse(pkg.itinerary   || "[]"),
      flight:    JSON.parse(pkg.flight_info  || "null"),
      hotel:     JSON.parse(pkg.hotel_info   || "null"),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch package" });
  }
});

// ─── SUBSCRIPTION ROUTES ───────────────────────────────────────────────────────

app.get("/api/subscription/plans", (req, res) => {
  res.json([
    {
      id: "explorer", name: "Explorer", price: 29, yearlyPrice: 249,
      features: ["1 AI package/month", "Curated deals", "Basic matching", "Email support"],
    },
    {
      id: "voyager", name: "Voyager", price: 59, yearlyPrice: 499, highlighted: true,
      features: ["3 AI packages/month", "Full personalization", "Priority reservations", "Chat support"],
    },
    {
      id: "elite", name: "Elite", price: 129, yearlyPrice: 999,
      features: ["Unlimited AI packages", "Hyper-personalization", "VIP access", "24/7 concierge"],
    },
  ]);
});

app.post("/api/subscription/subscribe", verifyToken, async (req, res) => {
  const { planId, billingPeriod = "monthly" } = req.body;

  if (!["explorer", "voyager", "elite"].includes(planId)) {
    return res.status(400).json({ error: "Invalid plan" });
  }

  try {
    const expiresAt = new Date();
    if (billingPeriod === "yearly") {
      expiresAt.setFullYear(expiresAt.getFullYear() + 1);
    } else {
      expiresAt.setMonth(expiresAt.getMonth() + 1);
    }

    await query(
      `INSERT INTO subscriptions (user_id, plan_id, billing_period, status, expires_at)
       VALUES ($1,$2,$3,'active',$4)
       ON CONFLICT (user_id) DO UPDATE SET
         plan_id        = EXCLUDED.plan_id,
         billing_period = EXCLUDED.billing_period,
         status         = 'active',
         expires_at     = EXCLUDED.expires_at`,
      [req.userId, planId, billingPeriod, expiresAt.toISOString()]
    );

    await query(
      `INSERT INTO memberships (user_id, membership_type, membership_expires)
       VALUES ($1,$2,$3)
       ON CONFLICT (user_id) DO UPDATE SET
         membership_type    = EXCLUDED.membership_type,
         membership_expires = EXCLUDED.membership_expires`,
      [req.userId, planId, expiresAt.toISOString()]
    );

    res.json({
      success:      true,
      subscription: { planId, billingPeriod, expiresAt: expiresAt.toISOString() },
    });
  } catch (err) {
    console.error("Subscribe error:", err);
    res.status(500).json({ error: "Failed to create subscription" });
  }
});

app.get("/api/subscription", verifyToken, async (req, res) => {
  try {
    const result = await query(
      "SELECT * FROM subscriptions WHERE user_id = $1",
      [req.userId]
    );
    if (result.rows.length === 0) return res.json(null);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch subscription" });
  }
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// ─── START ────────────────────────────────────────────────────────────────────

initDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`🚀 Server running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
