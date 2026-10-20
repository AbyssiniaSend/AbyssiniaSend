
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const requiredEnv = [
  "DATABASE_URL postgresql://abyssiniasend_db_user:TbLFzANJscH1P7sl7VpUQiYwA0pTaXcQ@dpg-dbbql3o473hc738ghsbg-a/abyssiniasend_db",
  "SESSION_SECRET 1e1cc6464318fb1dcb46c384168de87a04f1f83077ba8530ec21f29a9d4322f2",
  "ADMIN_EMAIL abrahamjejaw@gmail.com",
  "ADMIN_PASSWORD @Abraham24;199324"
];

for (const key of requiredEnv) {
  if (!process.env[key] || !process.env[key].trim()) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

if (process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error("ADMIN_PASSWORD must be at least 12 characters.");
}

const ADMIN_EMAIL = process.env.ADMIN_EMAIL.trim().toLowerCase();

if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ADMIN_EMAIL)) {
  throw new Error("ADMIN_EMAIL must be a valid email address.");
}

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "disable"
      ? false
      : { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error.message);
});

app.use(
  session({
    name: "abyssiniasend.sid",
    store: new PgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
      path: "/"
    }
  })
);

function safeUser(user) {
  return {
    id: user.id,
    fullName: user.full_name,
    email: user.email,
    role: user.role
  };
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access only."
    });
  }

  next();
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    req.session.destroy((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const adminName = (
    process.env.ADMIN_NAME || "AbyssiniaSend Admin"
  ).trim();

  const adminHash = await bcrypt.hash(
    process.env.ADMIN_PASSWORD,
    12
  );

  // Only the configured administrator email should have admin role.
  await pool.query(
    `UPDATE app_users
     SET role = 'user'
     WHERE LOWER(email) <> $1 AND role = 'admin'`,
    [ADMIN_EMAIL]
  );

  await pool.query(
    `INSERT INTO app_users
       (full_name, email, password_hash, role)
     VALUES ($1, $2, $3, 'admin')
     ON CONFLICT (email)
     DO UPDATE SET
       full_name = EXCLUDED.full_name,
       password_hash = EXCLUDED.password_hash,
       role = 'admin'`,
    [adminName, ADMIN_EMAIL, adminHash]
  );

  console.log("PostgreSQL ready. Admin account configured.");
}

// Serve the website.
app.get("/", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "index.html"));
});

// Check the current session.
app.get("/api/me", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.session.user) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  return res.json({ user: req.session.user });
});

// Register a regular customer account.
app.post("/api/register", async (req, res, next) => {
  try {
    const { fullName, email, password } = req.body || {};

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Enter your name, email and password."
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (
      cleanName.length < 2 ||
      cleanName.length > 120 ||
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Check your name, email and password requirements."
      });
    }

    if (cleanEmail === ADMIN_EMAIL) {
      return res.status(403).json({
        error: "This email is reserved for the administrator."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO app_users
         (full_name, email, password_hash, role)
       VALUES ($1, $2, $3, 'user')
       ON CONFLICT (email) DO NOTHING
       RETURNING id, full_name, email, role`,
      [cleanName, cleanEmail, passwordHash]
    );

    if (result.rowCount === 0) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const user = safeUser(result.rows[0]);

    await regenerateSession(req);
    req.session.user = user;
    await saveSession(req);

    return res.status(201).json({
      message: "Account created successfully.",
      user
    });
  } catch (error) {
    next(error);
  }
});

// Log in a customer or the configured administrator.
app.post("/api/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Enter a valid email and password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, full_name, email, password_hash, role
       FROM app_users
       WHERE email = $1`,
      [cleanEmail]
    );

    const userRecord = result.rows[0];

    const passwordMatches = userRecord
      ? await bcrypt.compare(password, userRecord.password_hash)
      : false;

    if (!userRecord || !passwordMatches) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const role =
      userRecord.email.toLowerCase() === ADMIN_EMAIL
        ? "admin"
        : "user";

    const user = safeUser({
      ...userRecord,
      role
    });

    await regenerateSession(req);
    req.session.user = user;
    await saveSession(req);

    return res.json({
      message: "Login successful.",
      user
    });
  } catch (error) {
    next(error);
  }
});

// Log out and invalidate the session.
app.post("/api/logout", async (req, res, next) => {
  try {
    await destroySession(req);

    res.clearCookie("abyssiniasend.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    return res.json({
      message: "Logged out successfully."
    });
  } catch (error) {
    next(error);
  }
});

// Example protected customer endpoint.
app.get("/api/account", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, role, created_at
       FROM app_users
       WHERE id = $1`,
      [req.session.user.id]
    );

    if (!result.rows[0]) {
      return res.status(401).json({
        error: "Please log in again."
      });
    }

    return res.json({
      user: safeUser(result.rows[0]),
      createdAt: result.rows[0].created_at
    });
  } catch (error) {
    next(error);
  }
});

// Admin-only authorization check.
app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  return res.json({
    authorized: true,
    user: req.session.user
  });
});

// List customer accounts: administrator only.
app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, full_name, email, role, created_at
       FROM app_users
       ORDER BY created_at DESC
       LIMIT 500`
    );

    return res.json({
      users: result.rows.map(safeUser)
    });
  } catch (error) {
    next(error);
  }
});

// Handle errors without exposing internal details to visitors.
app.use((error, req, res, next) => {
  console.error("Request failed:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: "A server error occurred. Please try again."
  });
});

// Start only after PostgreSQL is ready.
async function start() {
  await initializeDatabase();
  await pool.query("SELECT 1");

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`AbyssiniaSend listening on port ${PORT}`);
  });
}

start().catch((error) => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
