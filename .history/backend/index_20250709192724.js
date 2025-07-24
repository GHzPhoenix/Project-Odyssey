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
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const Database = require("better-sqlite3");
const db = new Database(dbPath, { timeout: 5000 });

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@travel.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin123!";
const existingAdmin = db
  .prepare("SELECT id FROM users WHERE email = ?")
  .get(ADMIN_EMAIL);
if (!existingAdmin) {
  const hashed = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)").run(
    "Administrator",
    ADMIN_EMAIL,
    hashed,
    "admin"
  );
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  membership_type TEXT NOT NULL,
  membership_expires TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS deals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  activities TEXT,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  image_url TEXT NOT NULL,
  price REAL NOT NULL CHECK(price >= 0),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
CREATE TABLE IF NOT EXISTS paypal_transactions (
  id TEXT PRIMARY KEY,
  reference_id TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL,
  create_time TEXT NOT NULL,
  user_email TEXT,
  deal_name TEXT
);
`);

function runAll(sql, params = []) {
  return db.prepare(sql).all(...params);
}

function runExec(sql, params = []) {
  return db.prepare(sql).run(...params);
}

function createPayPalClient() {
  const env =
    process.env.PAYPAL_ENV === "production"
      ? new paypal.core.LiveEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_SECRET
        )
      : new paypal.core.SandboxEnvironment(
          process.env.PAYPAL_CLIENT_ID,
          process.env.PAYPAL_SECRET
        );
  return new paypal.core.PayPalHttpClient(env);
}

const ppClient = createPayPalClient();

const app = express();
const port = process.env.PORT || 5002;

app.use(express.json({ limit: "10mb" }));
app.use(
  cors({
    origin: "http://127.0.0.1:5500",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
    optionsSuccessStatus: 204,
  })
);

app.options("*", (req, res) => res.sendStatus(204));

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : null;
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

function verifyAdmin(req, res, next) {
  if (req.userRole !== "admin")
    return res.status(403).json({ error: "Admin access required" });
  next();
}

app.get("/", (req, res) => res.json({ status: "Server is running" }));

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !email?.trim() || !password?.trim())
    return res.status(400).json({ error: "All fields required" });
  if (password.length < 8)
    return res.status(400).json({ error: "Password must be 8+ characters" });
  const existing = runAll("SELECT id FROM users WHERE email = ?", [
    email.trim(),
  ]);
  if (existing.length) return res.status(409).json({ error: "Email exists" });
  const hashedPassword = await bcrypt.hash(password, 10);
  const info = runExec(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name.trim(), email.trim(), hashedPassword]
  );
  const user = runAll("SELECT id, name, email, role FROM users WHERE id = ?", [
    info.lastInsertRowid,
  ])[0];
  res.status(201).json(user);
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email?.trim() || !password?.trim())
    return res.status(400).json({ error: "Email and password required" });
  const rows = runAll("SELECT * FROM users WHERE email = ?", [email.trim()]);
  if (!rows.length)
    return res.status(401).json({ error: "Invalid credentials" });
  const user = rows[0];
  const validPassword =
    user.role === "admin"
      ? password === user.password
      : await bcrypt.compare(password, user.password);
  if (!validPassword)
    return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

app.get("/api/membership", verifyToken, (req, res) => {
  const row = runAll(
    "SELECT membership_type, membership_expires FROM memberships WHERE user_id = ?",
    [req.userId]
  )[0];
  if (!row) return res.status(404).json({ error: "No membership found" });
  res.json(row);
});

app.post("/api/membership/renew", verifyToken, (req, res) => {
  const existing = runAll(
    "SELECT membership_type, membership_expires FROM memberships WHERE user_id = ?",
    [req.userId]
  )[0];
  const now = new Date();
  let base = now;
  if (
    existing?.membership_expires &&
    new Date(existing.membership_expires) > now
  )
    base = new Date(existing.membership_expires);
  const nextDate = new Date(base);
  nextDate.setFullYear(nextDate.getFullYear() + 1);
  const isoDate = nextDate.toISOString().split("T")[0];
  if (existing)
    runExec("UPDATE memberships SET membership_expires = ? WHERE user_id = ?", [
      isoDate,
      req.userId,
    ]);
  else
    runExec(
      "INSERT INTO memberships (user_id, membership_type, membership_expires) VALUES (?, ?, ?)",
      [req.userId, existing?.membership_type || "Premium Plan", isoDate]
    );
  res.json({
    membershipType: existing?.membership_type || "Premium Plan",
    expiresAt: isoDate,
  });
});

app.post(
  "/api/membership/purchase",
  verifyToken,
  express.json(),
  async (req, res) => {
    const userId = req.userId;
    const planId = "Premium";
    const existing = runAll(
      "SELECT membership_expires FROM memberships WHERE user_id = ?",
      [userId]
    )[0];
    let base = new Date();
    if (existing && new Date(existing.membership_expires) > base)
      base = new Date(existing.membership_expires);
    const nextDate = new Date(base);
    nextDate.setFullYear(nextDate.getFullYear() + 1);
    const isoDate = nextDate.toISOString().split("T")[0];
    if (existing)
      runExec(
        "UPDATE memberships SET membership_type = ?, membership_expires = ? WHERE user_id = ?",
        [planId, isoDate, userId]
      );
    else
      runExec(
        "INSERT INTO memberships (user_id, membership_type, membership_expires) VALUES (?, ?, ?)",
        [userId, planId, isoDate]
      );
    const updated = runAll(
      "SELECT membership_type AS membershipType, membership_expires AS membershipExpires FROM memberships WHERE user_id = ?",
      [userId]
    )[0];
    res.json(updated);
  }
);

app.get("/api/deals", (req, res) => {
  const deals = runAll("SELECT * FROM deals ORDER BY id DESC");
  res.json(deals);
});

app.get("/api/deals/:id", (req, res) => {
  const deal = runAll("SELECT * FROM deals WHERE id = ?", [req.params.id])[0];
  if (!deal) return res.status(404).json({ error: "Deal not found" });
  res.json(deal);
});

app.post("/api/deals", verifyToken, verifyAdmin, (req, res) => {
  const { name, location, activities, start_date, end_date, image_url, price } =
    req.body;
  if (
    !name ||
    !location ||
    !activities ||
    !start_date ||
    !end_date ||
    !image_url ||
    price == null
  )
    return res.status(400).json({ error: "Missing required fields" });
  const p = parseFloat(price);
  if (isNaN(p) || p < 0)
    return res.status(400).json({ error: "Invalid price" });
  const info = runExec(
    "INSERT INTO deals (name, location, activities, start_date, end_date, image_url, price) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [name, location, activities, start_date, end_date, image_url, p]
  );
  const newDeal = runAll("SELECT * FROM deals WHERE id = ?", [
    info.lastInsertRowid,
  ])[0];
  res.status(201).json(newDeal);
});

app.put("/api/deals/:id", verifyToken, verifyAdmin, (req, res) => {
  const { name, location, activities, start_date, end_date, price } = req.body;
  if (
    !name ||
    !location ||
    !activities ||
    !start_date ||
    !end_date ||
    price == null
  )
    return res.status(400).json({ error: "Missing required fields" });
  const p = parseFloat(price);
  if (isNaN(p) || p < 0)
    return res.status(400).json({ error: "Invalid price**" });
  db.prepare(
    "UPDATE deals SET name=?, location=?, activities=?, start_date=?, end_date=?, price=? WHERE id=?"
  ).run(name, location, activities, start_date, end_date, p, req.params.id);
  const updated = db
    .prepare("SELECT * FROM deals WHERE id=?")
    .get(req.params.id);
  res.json(updated);
});

app.delete("/api/deals/:id", verifyToken, verifyAdmin, (req, res) => {
  db.prepare("DELETE FROM deals WHERE id=?").run(req.params.id);
  res.json({ message: "Deal deleted" });
});

app.post("/api/inquiries", (req, res) => {
  const { name, email, destination, dates, guests, budget, preferences } =
    req.body;
  if (!name || !email || !destination || !dates || !guests || !budget)
    return res.status(400).json({ error: "Missing required fields" });
  const info = runExec(
    "INSERT INTO inquiries (name,email,destination,dates,guests,budget,preferences) VALUES (?,?,?,?,?,?,?)",
    [name, email, destination, dates, guests, budget, preferences]
  );
  const inq = runAll("SELECT * FROM inquiries WHERE id = ?", [
    info.lastInsertRowid,
  ])[0];
  res.status(201).json(inq);
});

app.get("/api/inquiries", verifyToken, verifyAdmin, (req, res) => {
  const list = runAll("SELECT * FROM inquiries ORDER BY created_at DESC");
  res.json(list);
});

app.get("/api/bookings", verifyToken, (req, res) => {
  const rows = runAll(
    "SELECT id, deal_id, destination, start_date, end_date, guests FROM bookings WHERE user_id = ? ORDER BY created_at DESC",
    [req.userId]
  );
  res.json(rows);
});

app.post("/api/bookings", verifyToken, (req, res) => {
  const { deal_id, destination, start_date, end_date, guests } = req.body;
  if (
    !deal_id ||
    !destination ||
    !start_date ||
    !end_date ||
    !guests ||
    guests < 1
  )
    return res.status(400).json({ error: "Missing required fields**" });
  const info = runExec(
    "INSERT INTO bookings (user_id, deal_id, destination, start_date, end_date, guests) VALUES (?,?,?,?,?,?)",
    [req.userId, deal_id, destination, start_date, end_date, guests]
  );
  const booking = runAll(
    "SELECT id, deal_id, destination, start_date, end_date, guests FROM bookings WHERE id = ?",
    [info.lastInsertRowid]
  )[0];
  res.status(201).json(booking);
});

app.delete("/api/bookings/:id", verifyToken, (req, res) => {
  const bookingId = Number(req.params.id);
  const row = db
    .prepare("SELECT user_id FROM bookings WHERE id = ?")
    .get(bookingId);
  if (!row) return res.status(404).json({ error: "Booking not found" });
  if (row.user_id !== req.userId && req.userRole !== "admin")
    return res.status(403).json({ error: "Not authorized" });
  db.prepare("DELETE FROM bookings WHERE id = ?").run(bookingId);
  res.json({ message: "Booking canceled successfully" });
});

app.get("/api/bookings/all", verifyToken, verifyAdmin, (req, res) => {
  const rows = db
    .prepare(
      `SELECT b.id, b.user_id, u.name AS user_name, u.email AS user_email, b.deal_id, d.name AS deal_name, b.start_date, b.end_date, b.guests, b.created_at FROM bookings b JOIN users u ON u.id = b.user_id JOIN deals d ON d.id = b.deal_id ORDER BY b.created_at DESC`
    )
    .all();
  res.json(rows);
});

app.get("/api/users", verifyToken, verifyAdmin, (req, res) => {
  const users = runAll(
    `SELECT u.id, u.name, u.email, u.role, m.membership_expires AS membershipExpires FROM users u LEFT JOIN memberships m ON m.user_id = u.id ORDER BY u.id`
  );
  res.json(users);
});

app.put("/api/users/:id", verifyToken, verifyAdmin, (req, res) => {
  const userId = Number(req.params.id);
  const { name, email, role } = req.body;
  if (!name || !email || !role)
    return res.status(400).json({ error: "Name,email,role required" });
  if (userId === req.userId && role !== req.userRole)
    return res.status(403).json({ error: "Cannot change own role" });
  db.prepare("UPDATE users SET name=?, email=?, role=? WHERE id=?").run(
    name.trim(),
    email.trim(),
    role,
    userId
  );
  const updated = db
    .prepare("SELECT id,name,email,role FROM users WHERE id = ?")
    .get(userId);
  res.json(updated);
});

app.delete("/api/users/:id", verifyToken, verifyAdmin, (req, res) => {
  const userId = Number(req.params.id);
  if (userId === req.userId)
    return res.status(403).json({ error: "Cannot delete own account" });
  db.prepare("DELETE FROM users WHERE id=?").run(userId);
  res.json({ message: "User deleted successfully" });
});

app.get("/api/config/paypal", (req, res) =>
  res.json({ clientId: process.env.PAYPAL_CLIENT_ID })
);

app.post("/api/paypal/order", verifyToken, async (req, res) => {
  const { planId } = req.body;
  const request = new paypal.orders.OrdersCreateRequest();
  request.prefer("return=representation");
  request.requestBody({
    intent: "CAPTURE",
    purchase_units: [
      {
        reference_id: planId,
        amount: {
          currency_code: "EUR",
          value: planId === "premium" ? "99.00" : "49.00",
        },
      },
    ],
  });
  const order = await ppClient.execute(request);
  res.json({
    orderID: order.result.id,
    approveLink: order.result.links.find((l) => l.rel === "approve").href,
  });
});

app.post("/api/paypal/capture/:orderID", verifyToken, async (req, res) => {
  const { orderID } = req.params;
  const request = new paypal.orders.OrdersCaptureRequest(orderID);
  request.requestBody({});
  try {
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
      `INSERT OR IGNORE INTO paypal_transactions (id,reference_id,amount,currency,create_time,user_email,deal_name) VALUES (?,?,?,?,?,?,?)`,
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
    res.json({ capture: captureResponse.result });
  } catch (err) {
    const isAlready =
      err.statusCode === 422 &&
      err._originalError?.text?.includes("ORDER_ALREADY_CAPTURED");
    if (isAlready) {
      const getReq = new paypal.orders.OrdersGetRequest(orderID);
      const details = await ppClient.execute(getReq);
      return res.json({ capture: details.result });
    }
    res.status(500).json({ error: "Could not capture PayPal order" });
  }
});

app.get("/api/paypal/transactions", verifyToken, verifyAdmin, (req, res) => {
  const txns = runAll(
    `SELECT id,reference_id,deal_name,user_email,amount,currency,create_time FROM paypal_transactions ORDER BY create_time DESC`
  );
  res.json(txns);
});

app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
