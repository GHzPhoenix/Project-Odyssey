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
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  deal_id       INTEGER NOT NULL,
  destination   TEXT    NOT NULL,
  start_date    TEXT    NOT NULL,
  end_date      TEXT    NOT NULL,
  guests        INTEGER NOT NULL CHECK(guests > 0),
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  cancelled_at  DATETIME DEFAULT NULL,
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

  CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    travel_style TEXT,
    activities TEXT,
    cuisines TEXT,
    dietary_restrictions TEXT,
    budget_tier TEXT,
    companions TEXT,
    pace_preference TEXT,
    accommodation TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS generated_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    destination TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    duration INTEGER NOT NULL,
    guests INTEGER NOT NULL,
    price REAL,
    itinerary TEXT,
    flight_info TEXT,
    hotel_info TEXT,
    status TEXT DEFAULT 'draft',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    plan_id TEXT NOT NULL,
    billing_period TEXT NOT NULL DEFAULT 'monthly',
    status TEXT NOT NULL DEFAULT 'active',
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
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
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
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
  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,DELETE,PATCH,OPTIONS"
  );
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
          u.created_at,
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

app.get("/api/users/summary", verifyToken, verifyAdmin, (req, res) => {
  try {
    const { total } = db.prepare(`SELECT COUNT(*) AS total FROM users`).get();

    const { admins } = db
      .prepare(`SELECT COUNT(*) AS admins FROM users WHERE role = 'admin'`)
      .get();

    const { standard } = db
      .prepare(`SELECT COUNT(*) AS standard FROM users WHERE role = 'user'`)
      .get();

    res.json({
      total_users: total,
      total_admins: admins,
      total_standard: standard,
    });
  } catch (err) {
    console.error("Fetch user summary error:", err);
    res.status(500).json({ error: "Failed to fetch user summary" });
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

app.get("/api/users/all", verifyToken, verifyAdmin, (req, res) => {
  try {
    const users = db
      .prepare(
        `SELECT id, name, email, role, created_at
           FROM users
           ORDER BY id`
      )
      .all();
    res.json(users);
  } catch (err) {
    console.error("Fetch all users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});
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

app.get("/api/bookings/all", verifyToken, (req, res) => {
  try {
    const stats = db
      .prepare(
        `
        SELECT
          COUNT(*) AS total_bookings,
          SUM(guests) AS total_guests,
          SUM(CASE WHEN cancelled_at IS NULL THEN 1 ELSE 0 END) AS active_bookings,
          SUM(CASE WHEN cancelled_at IS NOT NULL THEN 1 ELSE 0 END) AS cancelled_bookings
        FROM bookings
      `
      )
      .get();

    res.json(stats);
  } catch (err) {
    console.error("Fetch booking stats error:", err);
    res.status(500).json({ error: "Failed to fetch booking data" });
  }
});

app.get("/api/bookings/summary", verifyToken, verifyAdmin, (req, res) => {
  try {
    const row = db
      .prepare(
        `
          SELECT
            COUNT(*) AS total_bookings,
            COALESCE(SUM(guests),0) AS total_guests,
            SUM(CASE WHEN cancelled_at IS NULL THEN 1 ELSE 0 END) AS active_bookings,
            SUM(CASE WHEN cancelled_at IS NOT NULL THEN 1 ELSE 0 END) AS cancelled_bookings
          FROM bookings
        `
      )
      .get();
    res.json(row);
  } catch (err) {
    console.error("Fetch bookings summary error:", err);
    res.status(500).json({ error: "Failed to fetch bookings summary" });
  }
});

app.patch("/api/bookings/:id/cancel", verifyToken, (req, res) => {
  const bookingId = Number(req.params.id);
  if (isNaN(bookingId))
    return res.status(400).json({ error: "Invalid booking ID" });

  const booking = db
    .prepare(`SELECT user_id, cancelled_at FROM bookings WHERE id = ?`)
    .get(bookingId);

  if (!booking) return res.status(404).json({ error: "Booking not found" });
  if (booking.user_id !== req.userId && req.userRole !== "admin") {
    return res
      .status(403)
      .json({ error: "Not authorized to cancel this booking" });
  }
  if (booking.cancelled_at) {
    return res.status(400).json({ error: "Booking already cancelled" });
  }

  const now = new Date().toISOString();
  db.prepare(`UPDATE bookings SET cancelled_at = ? WHERE id = ?`).run(
    now,
    bookingId
  );

  res.json({ message: "Booking cancelled", cancelled_at: now });
});

app.delete("/api/bookings/:id", verifyToken, (req, res) => {
  const bookingId = Number(req.params.id);
  if (isNaN(bookingId))
    return res.status(400).json({ error: "Invalid booking ID" });

  const row = db
    .prepare(`SELECT user_id FROM bookings WHERE id = ?`)
    .get(bookingId);
  if (!row) return res.status(404).json({ error: "Booking not found" });
  if (row.user_id !== req.userId && req.userRole !== "admin") {
    return res
      .status(403)
      .json({ error: "Not authorized to delete this booking" });
  }

  db.prepare(`DELETE FROM bookings WHERE id = ?`).run(bookingId);
  res.json({ message: "Booking deleted" });
});

app.get("/api/bookings/active", verifyToken, verifyAdmin, (req, res) => {
  try {
    const rows = db
      .prepare(
        `
          SELECT
            id,
            user_id,
            deal_id,
            destination,
            start_date,
            end_date,
            guests,
            created_at
          FROM bookings
          WHERE cancelled_at IS NULL
          ORDER BY created_at DESC
        `
      )
      .all();
    res.json(rows);
  } catch (err) {
    console.error("Fetch active bookings error:", err);
    res.status(500).json({ error: "Failed to fetch active bookings" });
  }
});

app.get("/api/bookings", verifyToken, (req, res) => {
  try {
    const rows = runAll(
      `SELECT id, deal_id, destination, start_date, end_date, guests
       FROM bookings
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("Fetch bookings error:", err);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});
app.get("/api/bookings/cancelled", verifyToken, verifyAdmin, (req, res) => {
  const rows = db
    .prepare(
      `
    SELECT id, destination, start_date, end_date, guests, cancelled_at 
    FROM bookings 
    WHERE cancelled_at IS NOT NULL 
    ORDER BY cancelled_at DESC
  `
    )
    .all();
  res.json(rows);
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

    const info = runExec(
      `INSERT INTO bookings
         (user_id, deal_id, destination, start_date, end_date, guests)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.userId, deal_id, destination, start_date, end_date, guests]
    );

    const booking = runAll(
      `SELECT id, deal_id, destination, start_date, end_date, guests
       FROM bookings
       WHERE id = ?`,
      [info.lastInsertRowid]
    )[0];

    return res.status(201).json(booking);
  } catch (err) {
    console.error("Create booking error:", err);
    return res.status(500).json({ error: "Failed to create booking" });
  }
});

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
        .prepare("SELECT name FROM deals WHERE id = ?")
        .get(pu.reference_id);
      dealName = dealRow ? dealRow.name : null;
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

// ─── USER PREFERENCES ────────────────────────────────────────────────────────

app.post("/api/preferences", verifyToken, (req, res) => {
  const userId = req.user.id;
  const {
    travelStyle, activities, cuisines, dietaryRestrictions,
    budgetTier, companions, pacePreference, accommodation,
  } = req.body;

  try {
    const stmt = db.prepare(`
      INSERT INTO user_preferences
        (user_id, travel_style, activities, cuisines, dietary_restrictions, budget_tier, companions, pace_preference, accommodation)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        travel_style = excluded.travel_style,
        activities = excluded.activities,
        cuisines = excluded.cuisines,
        dietary_restrictions = excluded.dietary_restrictions,
        budget_tier = excluded.budget_tier,
        companions = excluded.companions,
        pace_preference = excluded.pace_preference,
        accommodation = excluded.accommodation,
        updated_at = CURRENT_TIMESTAMP
    `);
    stmt.run(
      userId,
      travelStyle || null,
      JSON.stringify(activities || []),
      JSON.stringify(cuisines || []),
      JSON.stringify(dietaryRestrictions || []),
      budgetTier || null,
      companions || null,
      pacePreference || null,
      accommodation || null
    );
    res.json({ success: true, message: "Preferences saved" });
  } catch (err) {
    console.error("Save preferences error:", err);
    res.status(500).json({ error: "Failed to save preferences" });
  }
});

app.get("/api/preferences", verifyToken, (req, res) => {
  const userId = req.user.id;
  try {
    const prefs = db.prepare("SELECT * FROM user_preferences WHERE user_id = ?").get(userId);
    if (!prefs) return res.json(null);

    res.json({
      travelStyle: prefs.travel_style,
      activities: JSON.parse(prefs.activities || "[]"),
      cuisines: JSON.parse(prefs.cuisines || "[]"),
      dietaryRestrictions: JSON.parse(prefs.dietary_restrictions || "[]"),
      budgetTier: prefs.budget_tier,
      companions: prefs.companions,
      pacePreference: prefs.pace_preference,
      accommodation: prefs.accommodation,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch preferences" });
  }
});

// ─── AI PACKAGE GENERATION ───────────────────────────────────────────────────

app.post("/api/packages/generate", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { destination, startDate, endDate, guests } = req.body;

  if (!destination || !startDate || !endDate) {
    return res.status(400).json({ error: "destination, startDate, and endDate are required" });
  }

  try {
    // Fetch user preferences
    const prefs = db.prepare("SELECT * FROM user_preferences WHERE user_id = ?").get(userId);
    const startDt = new Date(startDate);
    const endDt = new Date(endDate);
    const duration = Math.ceil((endDt - startDt) / (1000 * 60 * 60 * 24));

    // Build AI prompt for package generation
    const preferenceContext = prefs ? `
      Travel style: ${prefs.travel_style || "flexible"}
      Activities: ${prefs.activities || "[]"}
      Cuisines: ${JSON.parse(prefs.cuisines || '[]').join(", ") || "any"}
      Dietary restrictions: ${JSON.parse(prefs.dietary_restrictions || '[]').join(", ") || "none"}
      Budget tier: ${prefs.budget_tier || "moderate"}
      Traveling with: ${prefs.companions || "partner"}
    ` : "No specific preferences set.";

    let itinerary = [];
    let flightInfo = null;
    let hotelInfo = null;
    let price = 0;

    // Try Claude API if key is available
    if (process.env.ANTHROPIC_API_KEY) {
      const Anthropic = require("@anthropic-ai/sdk");
      const client = new Anthropic();

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

        const content = message.content[0].type === "text" ? message.content[0].text : "";
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          itinerary = parsed.itinerary || [];
          flightInfo = parsed.flight || null;
          hotelInfo = parsed.hotel || null;
          price = parsed.price || 0;
        }
      } catch (aiErr) {
        console.error("AI generation error:", aiErr.message);
        // Fall through to mock generation
      }
    }

    // Mock generation if AI not available or failed
    if (itinerary.length === 0) {
      price = prefs?.budget_tier === "luxury" ? 5500 :
              prefs?.budget_tier === "premium" ? 3500 :
              prefs?.budget_tier === "budget" ? 1200 : 2200;

      itinerary = Array.from({ length: Math.min(duration, 7) }, (_, i) => {
        const d = new Date(startDt);
        d.setDate(d.getDate() + i);
        return {
          day: i + 1,
          date: d.toISOString().split("T")[0],
          title: `Day ${i + 1} in ${destination}`,
          description: `Explore ${destination} with curated experiences`,
          activities: [
            { name: "Morning walk", type: "leisure", duration: "1h", description: "Start your day exploring the city", icon: "walk" },
            { name: "Local lunch", type: "food", duration: "1.5h", description: "Authentic local cuisine", icon: "restaurant" },
            { name: "Evening experience", type: "culture", duration: "2h", description: "Curated evening activity", icon: "ticket" },
          ],
          meals: [
            { type: "breakfast", restaurant: "Hotel Restaurant", cuisine: "Continental", description: "Hotel breakfast", priceRange: "€€" },
            { type: "lunch", restaurant: "Local Bistro", cuisine: "Local", description: "Authentic local food", priceRange: "€€" },
            { type: "dinner", restaurant: "Recommended Restaurant", cuisine: "Fine Dining", description: "Evening dining", priceRange: "€€€" },
          ],
        };
      });

      flightInfo = {
        outbound: { airline: "Air France", flightNumber: "AF123", departure: "09:00", arrival: "13:00", duration: "3h", stops: 0 },
        return: { airline: "Air France", flightNumber: "AF456", departure: "16:00", arrival: "20:00", duration: "3h", stops: 0 },
        class: "Economy",
      };

      hotelInfo = {
        name: `${destination} Boutique Hotel`,
        stars: prefs?.budget_tier === "luxury" ? 5 : 4,
        location: `Central ${destination}`,
        description: `A carefully selected hotel in the heart of ${destination}`,
        amenities: ["WiFi", "Breakfast", "Gym", "Concierge"],
      };
    }

    // Save to database
    const result = db.prepare(`
      INSERT INTO generated_packages
        (user_id, destination, start_date, end_date, duration, guests, price, itinerary, flight_info, hotel_info, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated')
    `).run(
      userId, destination, startDate, endDate, duration, guests || 1, price,
      JSON.stringify(itinerary), JSON.stringify(flightInfo), JSON.stringify(hotelInfo)
    );

    const packageId = result.lastInsertRowid.toString();

    res.json({
      package: {
        id: packageId,
        destination,
        country: destination,
        startDate,
        endDate,
        duration,
        price,
        rating: 4.8,
        reviewCount: 0,
        isAIGenerated: true,
        badge: "AI Curated",
        summary: `A personalized ${duration}-day ${destination} experience crafted for you`,
        itinerary,
        flight: flightInfo,
        hotel: hotelInfo,
        included: ["Flights", "Hotel", "Restaurant Reservations", "Experience Tickets"],
        highlights: [`${duration} days in ${destination}`, "Curated for your preferences", "AI-powered itinerary"],
      },
    });
  } catch (err) {
    console.error("Package generation error:", err);
    res.status(500).json({ error: "Failed to generate package" });
  }
});

app.get("/api/packages/:id", verifyToken, (req, res) => {
  const { id } = req.params;
  try {
    const pkg = db.prepare("SELECT * FROM generated_packages WHERE id = ?").get(id);
    if (!pkg) return res.status(404).json({ error: "Package not found" });

    res.json({
      ...pkg,
      itinerary: JSON.parse(pkg.itinerary || "[]"),
      flight: JSON.parse(pkg.flight_info || "null"),
      hotel: JSON.parse(pkg.hotel_info || "null"),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch package" });
  }
});

// ─── SUBSCRIPTIONS ────────────────────────────────────────────────────────────

app.get("/api/subscription/plans", (req, res) => {
  res.json([
    {
      id: "explorer",
      name: "Explorer",
      price: 29,
      yearlyPrice: 249,
      features: ["1 AI package/month", "Curated deals", "Basic matching", "Email support"],
    },
    {
      id: "voyager",
      name: "Voyager",
      price: 59,
      yearlyPrice: 499,
      highlighted: true,
      features: ["3 AI packages/month", "Full personalization", "Priority reservations", "Chat support"],
    },
    {
      id: "elite",
      name: "Elite",
      price: 129,
      yearlyPrice: 999,
      features: ["Unlimited AI packages", "Hyper-personalization", "VIP access", "24/7 concierge"],
    },
  ]);
});

app.post("/api/subscription/subscribe", verifyToken, (req, res) => {
  const userId = req.user.id;
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

    const stmt = db.prepare(`
      INSERT INTO subscriptions (user_id, plan_id, billing_period, status, expires_at)
      VALUES (?, ?, ?, 'active', ?)
      ON CONFLICT(user_id) DO UPDATE SET
        plan_id = excluded.plan_id,
        billing_period = excluded.billing_period,
        status = 'active',
        expires_at = excluded.expires_at
    `);
    stmt.run(userId, planId, billingPeriod, expiresAt.toISOString());

    // Also update memberships table for compatibility
    const membershipStmt = db.prepare(`
      INSERT INTO memberships (user_id, membership_type, membership_expires)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        membership_type = excluded.membership_type,
        membership_expires = excluded.membership_expires
    `);
    membershipStmt.run(userId, planId, expiresAt.toISOString());

    res.json({
      success: true,
      subscription: { planId, billingPeriod, expiresAt: expiresAt.toISOString() },
    });
  } catch (err) {
    console.error("Subscribe error:", err);
    res.status(500).json({ error: "Failed to create subscription" });
  }
});

app.get("/api/subscription", verifyToken, (req, res) => {
  const userId = req.user.id;
  try {
    const sub = db.prepare("SELECT * FROM subscriptions WHERE user_id = ?").get(userId);
    if (!sub) return res.json(null);
    res.json(sub);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch subscription" });
  }
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

console.log("🔍 About to start Express server on port", port);
app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
