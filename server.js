
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const requiredEnv = [
  "DATABASE_URL",
  "SESSION_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD"
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

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;

const googleConfigured = Boolean(
  GOOGLE_CLIENT_ID &&
  GOOGLE_CLIENT_SECRET &&
  GOOGLE_CALLBACK_URL
);

const googleClient = googleConfigured
  ? new OAuth2Client(
      GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET,
      GOOGLE_CALLBACK_URL
    )
  : null;

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

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const first = Buffer.from(a);
  const second = Buffer.from(b);

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

function googleNotConfigured(res) {
  return res.status(503).send(
    "Google Login is not configured. Please try email and password login."
  );
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash TEXT,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE app_users
    ALTER COLUMN password_hash DROP NOT NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_accounts (
      id BIGSERIAL PRIMARY KEY,
      provider VARCHAR(30) NOT NULL,
      provider_user_id VARCHAR(255) NOT NULL,
      user_id BIGINT NOT NULL REFERENCES app_users(id)
        ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (provider, provider_user_id),
      UNIQUE (provider, user_id)
    )
  `);

  const adminName = (
    process.env.ADMIN_NAME || "AbyssiniaSend Admin"
  ).trim();

  const adminHash = await bcrypt.hash(
    process.env.ADMIN_PASSWORD,
    12
  );

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

/* Login page */
app.get("/login", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (req.session.user) {
    return res.redirect("/");
  }

  return res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/login.html", (req, res) => {
  return res.redirect("/login");
});

/* Start Google OAuth login */
app.get("/auth/google", async (req, res, next) => {
  try {
    if (!googleConfigured || !googleClient) {
      return googleNotConfigured(res);
    }

    const state = crypto.randomBytes(32).toString("hex");
    const nonce = crypto.randomBytes(32).toString("hex");

    req.session.googleOAuth = {
      state,
      nonce,
      createdAt: Date.now()
    };

    await saveSession(req);

    const url = googleClient.generateAuthUrl({
      response_type: "code",
      scope: ["openid", "email", "profile"],
      state,
      nonce,
      prompt: "select_account"
    });

    return res.redirect(url);
  } catch (error) {
    next(error);
  }
});

/* Google OAuth callback */
app.get("/auth/google/callback", async (req, res, next) => {
  try {
    if (!googleConfigured || !googleClient) {
      return googleNotConfigured(res);
    }

    const saved = req.session.googleOAuth;
    delete req.session.googleOAuth;

    if (
      !saved ||
      Date.now() - saved.createdAt > 10 * 60 * 1000 ||
      !sameSecret(req.query.state, saved.state)
    ) {
      await saveSession(req);
      return res.status(400).send(
        "Google login verification failed. Please start again."
      );
    }

    if (req.query.error) {
      await saveSession(req);
      return res.redirect("/login");
    }

    if (typeof req.query.code !== "string") {
      await saveSession(req);
      return res.status(400).send(
        "Google did not return an authorization code."
      );
    }

    const { tokens } = await googleClient.getToken({
      code: req.query.code,
      redirect_uri: GOOGLE_CALLBACK_URL
    });

    if (!tokens.id_token) {
      throw new Error("Google did not return an ID token.");
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const profile = ticket.getPayload();

    if (
      !profile ||
      !profile.sub ||
      !profile.email ||
      profile.email_verified !== true ||
      typeof profile.nonce !== "string" ||
      !sameSecret(profile.nonce, saved.nonce)
    ) {
      return res.status(401).send(
        "Google account verification failed. Please try again."
      );
    }

    const email = profile.email.trim().toLowerCase();
    const googleId = profile.sub;
    const fullName = (
      profile.name ||
      profile.given_name ||
      email.split("@")[0]
    ).trim().slice(0, 120);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).send("Google returned an invalid email.");
    }

    if (email === ADMIN_EMAIL) {
      return res.status(403).send(
        "Please use the administrator email and password login."
      );
    }

    let userRecord;

    const linked = await pool.query(
      `SELECT u.id, u.full_name, u.email, u.role
       FROM oauth_accounts o
       JOIN app_users u ON u.id = o.user_id
       WHERE o.provider = 'google'
         AND o.provider_user_id = $1`,
      [googleId]
    );

    if (linked.rows[0]) {
      userRecord = linked.rows[0];
    } else {
      const existing = await pool.query(
        `SELECT id FROM app_users WHERE email = $1`,
        [email]
      );

      if (existing.rows[0]) {
        return res.status(409).send(
          "An account already exists with this email. " +
          "Please sign in using that account's existing login method."
        );
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const inserted = await client.query(
          `INSERT INTO app_users
             (full_name, email, password_hash, role)
           VALUES ($1, $2, NULL, 'user')
           ON CONFLICT (email) DO NOTHING
           RETURNING id, full_name, email, role`,
          [fullName, email]
        );

        if (!inserted.rows[0]) {
          await client.query("ROLLBACK");
          return res.status(409).send(
            "An account already exists with this email. " +
            "Please sign in using the existing account."
          );
        }

        userRecord = inserted.rows[0];

        await client.query(
          `INSERT INTO oauth_accounts
             (provider, provider_user_id, user_id)
           VALUES ('google', $1, $2)`,
          [googleId, userRecord.id]
        );

        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    const user = safeUser({
      ...userRecord,
      role: userRecord.email.toLowerCase() === ADMIN_EMAIL
        ? "admin"
        : "user"
    });

    await regenerateSession(req);
    req.session.user = user;
    await saveSession(req);

    return res.redirect("/");
  } catch (error) {
    next(error);
  }
});

/* Admin Dashboard: admin account only */
app.get("/admin", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.session.user) {
    return res.redirect("/login");
  }

  if (req.session.user.role !== "admin") {
    return res.redirect("/");
  }

  return res.sendFile(path.join(__dirname, "admin.html"));
});

/* User Dashboard: regular users only */
app.get("/", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.session.user) {
    return res.redirect("/login");
  }

  if (req.session.user.role === "admin") {
    return res.redirect("/admin");
  }

  return res.sendFile(path.join(__dirname, "index.html"));
});

/* Check current login session */
app.get("/api/me", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!req.session.user) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  return res.json({ user: req.session.user });
});

/* Create a regular customer account */
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

/* Log in a customer or administrator */
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

    const passwordMatches =
      userRecord && userRecord.password_hash
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

    const user = safeUser({ ...userRecord, role });

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

/* Log out and invalidate the session */
app.post("/api/logout", async (req, res, next) => {
  try {
    if (req.session) {
      await destroySession(req);
    }

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

/* Protected customer account endpoint */
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

/* Administrator authorization check */
app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  return res.json({
    authorized: true,
    user: req.session.user
  });
});

/* List customer accounts: administrator only */
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

/* Unknown API routes return JSON */
app.use("/api", (req, res) => {
  return res.status(404).json({
    error: "API endpoint not found."
  });
});

/* Handle server errors */
app.use((error, req, res, next) => {
  console.error("Request failed:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: "A server error occurred. Please try again."
  });
});

/* Start only after PostgreSQL is ready */
async function start() {
  await initializeDatabase();
  await pool.query("SELECT 1");

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`AbyssiniaSend listening on port ${PORT}`);
    console.log(
      `Google OAuth: ${googleConfigured ? "configured" : "not configured"}`
    );
  });
}

start().catch((error) => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});
