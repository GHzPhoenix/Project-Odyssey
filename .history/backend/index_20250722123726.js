const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const paypal = require("@paypal/checkout-server-sdk");

const dbDir = path.join(__dirname, "../database");
const dbPath = path.join(dbDir, "travel_odyssey.db");

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;

const Database = require("better-sqlite3");
const db = new Database(dbPath, { timeout: 5000 });

console.log("✅ SQLite database opened at:", dbPath);

// Fixed database schema - consistent column names
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS paypal_transactions (
    id TEXT PRIMARY KEY,
    reference_id TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL,
    create_time TEXT NOT NULL,
    user_email TEXT,
    deal_name TEXT
  );

  CREATE TABLE IF NOT EXISTS deals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    rating REAL,
    description TEXT,
    price REAL NOT NULL CHECK(price >= 0),
    image_url TEXT NOT NULL,
    link TEXT,
    badge TEXT,
    name TEXT,
    location TEXT,
    activities TEXT,
    start_date TEXT,
    end_date TEXT,
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    destination TEXT NOT NULL,
    dates TEXT NOT NULL,
    guests INTEGER NOT NULL,
    budget REAL NOT NULL,
    preferences TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

function runAll(sql, params = []) {
  try {
    return db.prepare(sql).all(params);
  } catch (error) {
    console.error("Database query error:", error);
    throw error;
  }
}

function runExec(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    return stmt.run(params);
  } catch (error) {
    console.error("Database exec error:", error);
    throw error;
  }
}

const app = express();
const port = process.env.PORT || 5002;

const corsOptions = {
  origin: ["http://127.0.0.1:5500", "http://localhost:5500"],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(express.json({ limit: "10mb" }));
app.use(cors(corsOptions));

app.options("*", (req, res) => {
  res.header(
    "Access-Control-Allow-Origin",
    req.headers.origin || "http://127.0.0.1:5500"
  );
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.sendStatus(204);
});

// Middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

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

// Routes
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

    const existing = runAll("SELECT id FROM users WHERE email = ?", [
      email.trim(),
    ]);
    console.log("Existing lookup result:", existing);

    if (existing.length > 0) {
      console.log("Registration error: email already exists");
      return res.status(409).json({ error: "Email exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed password:", hashedPassword);

    const info = runExec(
      `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
      [name.trim(), email.trim(), hashedPassword]
    );
    console.log("Insert info:", info);

    const userId = info.lastInsertRowid;
    const user = runAll(
      "SELECT id, name, email, role FROM users WHERE id = ?",
      [userId]
    )[0];
    console.log("New user row:", user);

    return res.status(201).json(user);
  } catch (err) {
    console.error("Registration exception:", err);
    return res.status(500).json({ error: "Registration failed" });
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
      validPassword = password === user.password;
    } else {
      validPassword = await bcrypt.compare(password, user.password);
    }

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET not configured");
      return res.status(500).json({ error: "Server configuration error" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Membership routes
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
      expiresAt: isoDate,
    });
  } catch (err) {
    console.error("Renew membership error:", err);
    return res.status(500).json({ error: "Renewal failed" });
  }
});

// Deals routes
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
    const deal = runAll("SELECT * FROM deals WHERE id = ?", [req.params.id])[0];
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
      title,
      name,
      location,
      activities,
      start_date,
      end_date,
      image_url,
      price,
      description,
      rating,
      badge,
      link,
    } = req.body;

    // Use title or name for the title field
    const dealTitle = title || name;

    if (!dealTitle || !image_url || price == null) {
      return res.status(400).json({
        error:
          "Missing required fields: title/name, image_url, and price are required",
      });
    }

    const p = parseFloat(price);
    if (isNaN(p) || p < 0) {
      return res.status(400).json({ error: "Invalid price" });
    }

    const info = runExec(
      `INSERT INTO deals
         (title, name, location, activities, start_date, end_date, image_url, price, description, rating, badge, link)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        dealTitle,
        name,
        location,
        activities,
        start_date,
        end_date,
        image_url,
        p,
        description,
        rating,
        badge,
        link,
      ]
    );

    const dealId = info.lastInsertRowid;
    const newDeal = runAll("SELECT * FROM deals WHERE id = ?", [dealId])[0];
    return res.status(201).json(newDeal);
  } catch (err) {
    console.error("Create deal error:", err);
    return res.status(500).json({ error: "Failed to create deal" });
  }
});

app.put("/api/deals/:id", verifyToken, verifyAdmin, (req, res) => {
  try {
    const {
      title,
      name,
      location,
      activities,
      start_date,
      end_date,
      price,
      description,
      rating,
      badge,
      link,
    } = req.body;

    const dealTitle = title || name;

    if (!dealTitle || price == null) {
      return res
        .status(400)
        .json({ error: "Title/name and price are required" });
    }

    const p = parseFloat(price);
    if (isNaN(p) || p < 0) {
      return res.status(400).json({ error: "Invalid price" });
    }

    db.prepare(
      `UPDATE deals
         SET title=?, name=?, location=?, activities=?, start_date=?, end_date=?, price=?, description=?, rating=?, badge=?, link=?
       WHERE id=?`
    ).run(
      dealTitle,
      name,
      location,
      activities,
      start_date,
      end_date,
      p,
      description,
      rating,
      badge,
      link,
      req.params.id
    );

    const updated = db
      .prepare("SELECT * FROM deals WHERE id=?")
      .get(req.params.id);
    res.json(updated);
  } catch (err) {
    console.error("Update deal error:", err);
    res.status(500).json({ error: "Failed to update deal" });
  }
});

// Users routes
app.get("/api/users", verifyToken, verifyAdmin, (req, res) => {
  try {
    const users = db
      .prepare(
        `
          SELECT
            u.id,
            u.name,
            u.email,
            u.role,
            m.membership_expires AS membershipExpires
          FROM users u
          LEFT JOIN memberships m ON m.user_id = u.id
          ORDER BY u.id
        `
      )
      .all();
    res.json(users);
  } catch (err) {
    console.error("Fetch users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.put("/api/users/:id", verifyToken, verifyAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name, email, role } = req.body;

    if (!name || !email || !role) {
      return res
        .status(400)
        .json({ error: "Name, email and role are required" });
    }

    if (id === req.userId && role !== req.userRole) {
      return res.status(403).json({ error: "Cannot change your own role" });
    }

    db.prepare(
      `UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?`
    ).run(name.trim(), email.trim(), role, id);

    const updated = db
      .prepare(`SELECT id, name, email, role FROM users WHERE id = ?`)
      .get(id);
    res.json(updated);
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

app.delete("/api/users/:id", verifyToken, verifyAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid user ID" });
    if (id === req.userId) {
      return res.status(403).json({ error: "Cannot delete your own account" });
    }

    db.prepare(`DELETE FROM users WHERE id = ?`).run(id);
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// Inquiries routes
app.post("/api/inquiries", (req, res) => {
  try {
    const { name, email, destination, dates, guests, budget, preferences } =
      req.body;
    if (!name || !email || !destination || !dates || !guests || !budget) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const info = runExec(
      `INSERT INTO inquiries 
         (name, email, destination, dates, guests, budget, preferences)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, email, destination, dates, guests, budget, preferences]
    );

    const inq = runAll("SELECT * FROM inquiries WHERE id = ?", [
      info.lastInsertRowid,
    ])[0];
    res.status(201).json(inq);
  } catch (err) {
    console.error("Create inquiry error:", err);
    res.status(500).json({ error: "Failed to save inquiry" });
  }
});

app.get("/api/inquiries", verifyToken, verifyAdmin, (req, res) => {
  try {
    const list = runAll("SELECT * FROM inquiries ORDER BY created_at DESC");
    res.json(list);
  } catch (err) {
    console.error("Fetch inquiries error:", err);
    res.status(500).json({ error: "Failed to fetch inquiries" });
  }
});

// Updated bookings route to include cancelled_at field and handle the new column
app.get("/api/bookings/all", verifyToken, (req, res) => {
  try {
    // First, try to add the cancelled_at column if it doesn't exist
    try {
      db.exec(`ALTER TABLE bookings ADD COLUMN cancelled_at DATETIME`);
      console.log("Added cancelled_at column to bookings table");
    } catch (alterErr) {
      // Column probably already exists, continue silently
    }

    // Now fetch all bookings with the cancelled_at field
    const rows = db
      .prepare(
        `
        SELECT
          b.id AS id,
          u.name AS user_name,
          u.email AS user_email,
          d.name AS deal_name,
          b.destination,
          b.start_date,
          b.end_date,
          b.guests,
          b.created_at,
          b.cancelled_at
        FROM bookings b
        JOIN users u ON u.id = b.user_id
        JOIN deals d ON d.id = b.deal_id
        ORDER BY b.created_at DESC
      `
      )
      .all();

    console.log(`Found ${rows.length} bookings`);
    res.json(rows);
  } catch (err) {
    console.error("Fetch all bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// Also update the user's personal bookings endpoint to include cancelled_at
app.get("/api/bookings", verifyToken, (req, res) => {
  try {
    // Ensure cancelled_at column exists
    try {
      db.exec(`ALTER TABLE bookings ADD COLUMN cancelled_at DATETIME`);
    } catch (alterErr) {
      // Column probably already exists, continue silently
    }

    const rows = db
      .prepare(
        `
        SELECT
          b.id,
          b.deal_id,
          b.destination,
          b.start_date,
          b.end_date,
          b.guests,
          b.created_at,
          b.cancelled_at,
          d.title AS deal_name
        FROM bookings b
        LEFT JOIN deals d ON d.id = b.deal_id
        WHERE b.user_id = ?
        ORDER BY b.created_at DESC
      `
      )
      .all(req.userId);

    res.json(rows);
  } catch (err) {
    console.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

app.get("/api/bookings", verifyToken, (req, res) => {
  try {
    const rows = db
      .prepare(
        `
        SELECT
          id,
          deal_id,
          destination,
          start_date,
          end_date,
          guests
        FROM bookings
        WHERE user_id = ?
        ORDER BY created_at DESC
      `
      )
      .all(req.userId);
    res.json(rows);
  } catch (err) {
    console.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

app.post("/api/bookings", verifyToken, (req, res) => {
  try {
    const { deal_id, destination, start_date, end_date, guests } = req.body;
    if (
      !deal_id ||
      !destination ||
      !start_date ||
      !end_date ||
      !guests ||
      guests < 1
    ) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const info = db
      .prepare(
        `
        INSERT INTO bookings
          (user_id, deal_id, destination, start_date, end_date, guests)
        VALUES (?, ?, ?, ?, ?, ?)
      `
      )
      .run(req.userId, deal_id, destination, start_date, end_date, guests);

    const booking = db
      .prepare(
        `
        SELECT id, deal_id, destination, start_date, end_date, guests
        FROM bookings
        WHERE id = ?
      `
      )
      .get(info.lastInsertRowid);

    res.status(201).json(booking);
  } catch (err) {
    console.error("Create booking error:", err);
    res.status(500).json({ error: "Failed to create booking" });
  }
});
// Cancel booking route - users can cancel their own bookings, admins can cancel any booking
app.patch("/api/bookings/:id/cancel", verifyToken, (req, res) => {
  try {
    const bookingId = Number(req.params.id);

    if (isNaN(bookingId)) {
      return res.status(400).json({ error: "Invalid booking ID" });
    }

    // First, check if the booking exists and get its details
    const booking = db
      .prepare(
        `
        SELECT 
          b.id,
          b.user_id,
          b.destination,
          b.start_date,
          b.end_date,
          b.guests,
          b.created_at,
          u.name AS user_name,
          u.email AS user_email,
          d.title AS deal_name
        FROM bookings b
        JOIN users u ON u.id = b.user_id
        JOIN deals d ON d.id = b.deal_id
        WHERE b.id = ?
      `
      )
      .get(bookingId);

    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    // Check permissions: users can only cancel their own bookings, admins can cancel any
    if (req.userRole !== "admin" && booking.user_id !== req.userId) {
      return res.status(403).json({
        error: "You can only cancel your own bookings",
      });
    }

    // Add a cancelled_at timestamp to mark the booking as cancelled
    // We'll use an ALTER TABLE approach since the original schema doesn't have this field
    try {
      // Try to add the column if it doesn't exist (will fail silently if it already exists)
      db.exec(`ALTER TABLE bookings ADD COLUMN cancelled_at DATETIME`);
    } catch (alterErr) {
      // Column probably already exists, continue
    }

    // Update the booking to mark it as cancelled
    const now = new Date().toISOString();
    const updateResult = db
      .prepare(
        `
        UPDATE bookings 
        SET cancelled_at = ? 
        WHERE id = ? AND cancelled_at IS NULL
      `
      )
      .run(now, bookingId);

    if (updateResult.changes === 0) {
      return res.status(400).json({ error: "Booking is already cancelled" });
    }

    // Return the updated booking details
    const cancelledBooking = {
      id: booking.id,
      user_name: booking.user_name,
      user_email: booking.user_email,
      deal_name: booking.deal_name,
      destination: booking.destination,
      start_date: booking.start_date,
      end_date: booking.end_date,
      guests: booking.guests,
      created_at: booking.created_at,
      cancelled_at: now,
      cancelled_by: req.userRole === "admin" ? "admin" : "user",
    };

    res.json({
      message: "Booking cancelled successfully",
      booking: cancelledBooking,
    });
  } catch (err) {
    console.error("Cancel booking error:", err);
    res.status(500).json({ error: "Failed to cancel booking" });
  }
});
app.put("/api/bookings/:id", verifyToken, verifyAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    const { destination, start_date, end_date, guests } = req.body;
    if (!destination || !start_date || !end_date || !guests) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    db.prepare(
      `
      UPDATE bookings
      SET destination = ?, start_date = ?, end_date = ?, guests = ?
      WHERE id = ?
    `
    ).run(destination, start_date, end_date, guests, id);

    const updated = db
      .prepare(
        `
        SELECT id, destination, start_date, end_date, guests
        FROM bookings
        WHERE id = ?
      `
      )
      .get(id);

    res.json(updated);
  } catch (err) {
    console.error("Update booking error:", err);
    res.status(500).json({ error: "Failed to update booking" });
  }
});

app.delete("/api/bookings/:id", verifyToken, verifyAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid booking ID" });
    }
    db.prepare(`DELETE FROM bookings WHERE id = ?`).run(id);
    res.json({ message: "Booking deleted successfully" });
  } catch (err) {
    console.error("Delete booking error:", err);
    res.status(500).json({ error: "Failed to delete booking" });
  }
});

// PayPal routes
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

app.get("/api/config/paypal", (req, res) => {
  res.json({ clientId: PAYPAL_CLIENT_ID });
});

app.post("/api/paypal/order", verifyToken, async (req, res) => {
  try {
    const { planId } = req.body;
    const amount = planId === "premium" ? "99.00" : "49.00";

    const ppClient = createPayPalClient();
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");

    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [
        {
          reference_id: planId,
          amount: { currency_code: "EUR", value: amount },
        },
      ],
    });

    const order = await ppClient.execute(request);
    res.json({
      orderID: order.result.id,
      approveLink: order.result.links.find((l) => l.rel === "approve").href,
    });
  } catch (err) {
    console.error("PayPal create order error:", err);
    res.status(500).json({ error: "Could not create PayPal order" });
  }
});

app.post("/api/paypal/capture/:orderID", verifyToken, async (req, res) => {
  try {
    const { orderID } = req.params;
    const ppClient = createPayPalClient();
    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.requestBody({});

    const captureResponse = await ppClient.execute(request);
    const pu = captureResponse.result.purchase_units[0];
    const cap = pu.payments.captures[0];

    const userRow = db
      .prepare("SELECT email FROM users WHERE id = ?")
      .get(req.userId);
    const userEmail = userRow ? userRow.email : null;

    let dealName = null;
    if (/^\d+$/.test(pu.reference_id)) {
      const dealRow = db
        .prepare("SELECT title FROM deals WHERE id = ?")
        .get(pu.reference_id);
      dealName = dealRow ? dealRow.title : null;
    }

    runExec(
      `INSERT OR IGNORE INTO paypal_transactions
     (id, reference_id, amount, currency, create_time, user_email, deal_name)
   VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        cap.id,
        pu.reference_id,
        parseFloat(cap.amount.value),
        cap.amount.currency_code,
        cap.create_time,
        userEmail,
        dealName,
      ]
    );

    return res.json({ capture: captureResponse.result });
  } catch (err) {
    const isAlreadyCaptured =
      err.statusCode === 422 &&
      err._originalError?.text?.includes("ORDER_ALREADY_CAPTURED");

    if (isAlreadyCaptured) {
      try {
        const ppClient = createPayPalClient();
        const getRequest = new paypal.orders.OrdersGetRequest(orderID);
        const orderDetails = await ppClient.execute(getRequest);
        return res.json({ capture: orderDetails.result });
      } catch (getErr) {
        console.error("Failed to GET already-captured order:", getErr);
        return res
          .status(500)
          .json({ error: "Could not retrieve captured order details" });
      }
    }

    console.error("PayPal capture error:", err);
    return res.status(500).json({ error: "Could not capture PayPal order" });
  }
});

app.post("/api/membership/purchase", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const planId = "Premium";

    const existing = runAll(
      "SELECT membership_expires FROM memberships WHERE user_id = ?",
      [userId]
    )[0];

    let base = new Date();
    if (existing && new Date(existing.membership_expires) > base) {
      base = new Date(existing.membership_expires);
    }

    const next = new Date(base);
    next.setFullYear(next.getFullYear() + 1);
    const isoDate = next.toISOString().split("T")[0];

    if (existing) {
      runExec(
        "UPDATE memberships SET membership_type = ?, membership_expires = ? WHERE user_id = ?",
        [planId, isoDate, userId]
      );
    } else {
      runExec(
        "INSERT INTO memberships (user_id, membership_type, membership_expires) VALUES (?, ?, ?)",
        [userId, planId, isoDate]
      );
    }

    const updated = runAll(
      "SELECT membership_type AS membershipType, membership_expires AS membershipExpires FROM memberships WHERE user_id = ?",
      [userId]
    )[0];

    res.json(updated);
  } catch (err) {
    console.error("Purchase membership error:", err);
    res.status(500).json({ error: "Purchase failed" });
  }
});

app.get("/api/paypal/transactions", verifyToken, verifyAdmin, (req, res) => {
  try {
    const txns = runAll(`
      SELECT
        id,
        reference_id,
        deal_name,
        user_email,
        amount,
        currency,
        create_time
      FROM paypal_transactions
      ORDER BY create_time DESC`);

    res.json(txns);
  } catch (err) {
    console.error("Fetch transactions error:", err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
console.log("🔍 About to start Express server on port", port);
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
