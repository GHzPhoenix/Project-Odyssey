-- Travel Odyssey — PostgreSQL schema
-- Run once to initialise a fresh database, or use the auto-migration in index.js (initDB)

CREATE TABLE IF NOT EXISTS users (
  id         SERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL UNIQUE,
  password   TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deals (
  id          SERIAL PRIMARY KEY,
  title       TEXT NOT NULL,
  rating      NUMERIC,
  description TEXT,
  price       NUMERIC NOT NULL CHECK(price >= 0),
  image_url   TEXT NOT NULL,
  link        TEXT,
  badge       TEXT,
  name        TEXT,
  location    TEXT,
  activities  TEXT,
  start_date  TEXT,
  end_date    TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
  id                 SERIAL PRIMARY KEY,
  user_id            INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  membership_type    TEXT NOT NULL,
  membership_expires TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bookings (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  deal_id      INTEGER NOT NULL,
  destination  TEXT NOT NULL,
  start_date   TEXT NOT NULL,
  end_date     TEXT NOT NULL,
  guests       INTEGER NOT NULL CHECK(guests > 0),
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  cancelled_at TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS inquiries (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL,
  destination TEXT NOT NULL,
  dates       TEXT NOT NULL,
  guests      INTEGER NOT NULL,
  budget      NUMERIC NOT NULL,
  preferences TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_preferences (
  id                   SERIAL PRIMARY KEY,
  user_id              INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  travel_style         TEXT,
  activities           TEXT,
  cuisines             TEXT,
  dietary_restrictions TEXT,
  budget_tier          TEXT,
  companions           TEXT,
  pace_preference      TEXT,
  accommodation        TEXT,
  updated_at           TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS generated_packages (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  destination TEXT NOT NULL,
  start_date  TEXT NOT NULL,
  end_date    TEXT NOT NULL,
  duration    INTEGER NOT NULL,
  guests      INTEGER NOT NULL,
  price       NUMERIC,
  itinerary   TEXT,
  flight_info TEXT,
  hotel_info  TEXT,
  status      TEXT DEFAULT 'draft',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan_id        TEXT NOT NULL,
  billing_period TEXT NOT NULL DEFAULT 'monthly',
  status         TEXT NOT NULL DEFAULT 'active',
  started_at     TIMESTAMPTZ DEFAULT NOW(),
  expires_at     TEXT
);

CREATE TABLE IF NOT EXISTS paypal_transactions (
  id           TEXT PRIMARY KEY,
  reference_id TEXT NOT NULL,
  amount       NUMERIC NOT NULL,
  currency     TEXT NOT NULL,
  create_time  TEXT NOT NULL,
  user_email   TEXT,
  deal_name    TEXT
);

CREATE TABLE IF NOT EXISTS stripe_transactions (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  plan_id    TEXT NOT NULL,
  amount     INTEGER NOT NULL,
  currency   TEXT NOT NULL,
  status     TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
