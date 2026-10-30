const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const path = require("path");
const { rateLimit } = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Please try again in 15 minutes."
  }
});

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
    ALTER TABLE app_users
      ADD COLUMN IF NOT EXISTS first_name VARCHAR(60),
      ADD COLUMN IF NOT EXISTS last_name VARCHAR(60),
      ADD COLUMN IF NOT EXISTS country VARCHAR(100)
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transfer_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      currency VARCHAR(3) NOT NULL DEFAULT 'ETB',
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'confirmed', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS deposit_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      amount NUMERIC(18, 2) NOT NULL CHECK (amount > 0),
      currency VARCHAR(3) NOT NULL
        CHECK (currency IN ('USD', 'ETB')),
      note VARCHAR(200),
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'confirmed', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
    ALTER TABLE deposit_requests
      ADD COLUMN IF NOT EXISTS transaction_reference VARCHAR(150),
      ADD COLUMN IF NOT EXISTS receipt_url TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_settings (
      id BIGSERIAL PRIMARY KEY,
      method_name VARCHAR(100) NOT NULL,
      account_name VARCHAR(150),
      account_number VARCHAR(150),
      payment_link TEXT,
      instructions TEXT,
      currency VARCHAR(3) NOT NULL DEFAULT 'USD',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    ALTER TABLE deposit_requests
    ADD COLUMN IF NOT EXISTS payment_method_id BIGINT
    REFERENCES payment_settings(id)
    ON DELETE SET NULL
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_accounts (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      currency VARCHAR(3) NOT NULL DEFAULT 'USD',
      balance NUMERIC(18, 2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, currency)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      amount NUMERIC(18, 2) NOT NULL,
      currency VARCHAR(3) NOT NULL DEFAULT 'USD',
      transaction_type VARCHAR(30) NOT NULL,
      description TEXT,
      reference_id BIGINT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS support_messages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      sender_role VARCHAR(20) NOT NULL
        CHECK (sender_role IN ('user', 'admin')),
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_notifications (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES app_users(id),
      title VARCHAR(150) NOT NULL,
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_deposits_user
    ON deposit_requests(user_id, created_at DESC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_support_user
    ON support_messages(user_id, created_at ASC)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_notifications_user
    ON user_notifications(user_id, created_at DESC)
  `);

  const adminHash = await bcrypt.hash(
    process.env.ADMIN_PASSWORD,
    12
  );

  await pool.query(
    `INSERT INTO app_users
      (full_name, email, password_hash, role)
     VALUES ($1, $2, $3, 'admin')
     ON CONFLICT (email)
     DO UPDATE SET
       role = 'admin',
       password_hash = EXCLUDED.password_hash`,
    ["AbyssiniaSend Administrator", ADMIN_EMAIL, adminHash]
  );

  console.log("Database initialized successfully.");
}
// ========================================
// REGISTER
// ========================================

app.post("/api/register", loginLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Please provide all required fields."
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 120) {
      return res.status(400).json({
        error: "Name must be between 2 and 120 characters."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        error: "Invalid email address."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Password must contain 8–128 characters."
      });
    }

    const existing = await pool.query(
      "SELECT id FROM app_users WHERE email = $1",
      [cleanEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Email already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO app_users
       (full_name, email, password_hash, role)
       VALUES ($1, $2, $3, 'user')
       RETURNING id, full_name, email, role`,
      [cleanName, cleanEmail, passwordHash]
    );

    const user = result.rows[0];

    await pool.query(
      `INSERT INTO wallet_accounts (user_id, currency, balance)
       VALUES ($1, 'USD', 0)
       ON CONFLICT (user_id, currency) DO NOTHING`,
      [user.id]
    );

    await regenerateSession(req);

    req.session.user = safeUser(user);

    await saveSession(req);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      user: safeUser(user)
    });

  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});


// ========================================
// LOGIN
// ========================================

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, full_name, email, password_hash, role
       FROM app_users
       WHERE email = $1`,
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return res.status(401).json({
        error: "Please use Google Login for this account."
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    await regenerateSession(req);

    req.session.user = safeUser(user);

    await saveSession(req);

    res.json({
      success: true,
      message: "Login successful.",
      user: safeUser(user),
      redirect:
        user.role === "admin" ? "/admin" : "/"
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});


// ========================================
// CURRENT USER
// ========================================

app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    authenticated: true,
    user: req.session.user
  });
});


// ========================================
// LOGOUT
// ========================================

app.post("/api/logout", async (req, res) => {
  try {
    await destroySession(req);

    res.clearCookie("abyssiniasend.sid", {
      path: "/"
    });

    res.json({
      success: true,
      message: "Logged out successfully."
    });

  } catch (error) {
    console.error("Logout error:", error);

    res.status(500).json({
      error: "Logout failed."
    });
  }
});


// ========================================
// GOOGLE LOGIN
// ========================================

app.get("/auth/google", (req, res) => {
  if (!googleConfigured) {
    return googleNotConfigured(res);
  }

  const state = crypto.randomBytes(32).toString("hex");

  req.session.googleOAuthState = state;

  const authUrl = googleClient.generateAuthUrl({
    access_type: "online",
    scope: ["email", "profile"],
    state
  });

  res.redirect(authUrl);
});


// ========================================
// GOOGLE CALLBACK
// ========================================

app.get("/auth/google/callback", async (req, res) => {
  if (!googleConfigured) {
    return googleNotConfigured(res);
  }

  try {
    const { code, state, error } = req.query;

    if (error || !code || !state) {
      return res.redirect("/login.html?error=google");
    }

    if (
      typeof state !== "string" ||
      !req.session.googleOAuthState ||
      !sameSecret(state, req.session.googleOAuthState)
    ) {
      return res.status(403).send("Invalid Google OAuth state.");
    }

    delete req.session.googleOAuthState;

    const { tokens } = await googleClient.getToken(
      String(code)
    );

    googleClient.setCredentials(tokens);

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (
      !payload ||
      !payload.sub ||
      !payload.email ||
      payload.email_verified !== true
    ) {
      return res.status(401).send(
        "Google email verification is required."
      );
    }

    const googleId = payload.sub;
    const googleEmail = payload.email.toLowerCase();
    const fullName = payload.name || "Google User";

    const client = await pool.connect();

    let user;

    try {
      await client.query("BEGIN");

      const linked = await client.query(
        `SELECT u.*
         FROM oauth_accounts o
         JOIN app_users u ON u.id = o.user_id
         WHERE o.provider = 'google'
         AND o.provider_user_id = $1
         FOR UPDATE OF u`,
        [googleId]
      );

      if (linked.rows.length > 0) {
        user = linked.rows[0];
      } else {
        const existing = await client.query(
          `SELECT * FROM app_users
           WHERE email = $1
           FOR UPDATE`,
          [googleEmail]
        );

        if (existing.rows.length > 0) {
          user = existing.rows[0];
        } else {
          const created = await client.query(
            `INSERT INTO app_users
             (full_name, email, password_hash, role)
             VALUES ($1, $2, NULL, 'user')
             RETURNING *`,
            [fullName, googleEmail]
          );

          user = created.rows[0];
        }

        await client.query(
          `INSERT INTO oauth_accounts
           (provider, provider_user_id, user_id)
           VALUES ('google', $1, $2)
           ON CONFLICT (provider, provider_user_id)
           DO NOTHING`,
          [googleId, user.id]
        );
      }

      await client.query(
        `INSERT INTO wallet_accounts
         (user_id, currency, balance)
         VALUES ($1, 'USD', 0)
         ON CONFLICT (user_id, currency)
         DO NOTHING`,
        [user.id]
      );

      await client.query("COMMIT");

    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }

    await regenerateSession(req);

    req.session.user = safeUser(user);

    await saveSession(req);

    if (user.role === "admin") {
      return res.redirect("/admin");
    }

    res.redirect("/");

  } catch (error) {
    console.error("Google OAuth error:", error);

    res.redirect("/login.html?error=google");
  }
});
// ========================================
// GET WALLET BALANCE
// ========================================

app.get("/api/wallet", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;

    const result = await pool.query(
      `INSERT INTO wallet_accounts (user_id, currency, balance)
       VALUES ($1, 'USD', 0)
       ON CONFLICT (user_id, currency) DO NOTHING`,
      [userId]
    );

    const wallet = await pool.query(
      `SELECT balance, currency
       FROM wallet_accounts
       WHERE user_id = $1 AND currency = 'USD'`,
      [userId]
    );

    res.json({
      balance: Number(wallet.rows[0].balance),
      currency: wallet.rows[0].currency
    });

  } catch (error) {
    console.error("Wallet error:", error);

    res.status(500).json({
      error: "Could not load wallet."
    });
  }
});


// ========================================
// GET ACTIVE PAYMENT METHODS
// ========================================

app.get("/api/payment-methods", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, method_name, account_name,
              account_number, payment_link,
              instructions, currency
       FROM payment_settings
       WHERE is_active = TRUE
       ORDER BY id DESC`
    );

    res.json({
      paymentMethods: result.rows
    });

  } catch (error) {
    console.error("Payment methods error:", error);

    res.status(500).json({
      error: "Could not load payment methods."
    });
  }
});


// ========================================
// ========================================
// CREATE DEPOSIT REQUEST
// ========================================

app.post("/api/deposits", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;

    const {
      amount,
      currency,
      payment_method_id,
      transaction_reference,
      note
    } = req.body;

    const depositAmount = Number(amount);
    const methodId = Number(payment_method_id);

    const depositCurrency =
      typeof currency === "string"
        ? currency.trim().toUpperCase()
        : "";

    const reference =
      typeof transaction_reference === "string"
        ? transaction_reference.trim()
        : "";

    const cleanNote =
      typeof note === "string"
        ? note.trim().slice(0, 200)
        : "";

    if (
      !Number.isFinite(depositAmount) ||
      depositAmount <= 0 ||
      depositAmount > 1000000
    ) {
      return res.status(400).json({
        error: "Enter a valid deposit amount."
      });
    }

    if (!["USD", "ETB"].includes(depositCurrency)) {
      return res.status(400).json({
        error: "Unsupported currency."
      });
    }

    if (
      !Number.isSafeInteger(methodId) ||
      methodId <= 0
    ) {
      return res.status(400).json({
        error: "Please select a valid payment method."
      });
    }

    if (!reference || reference.length > 150) {
      return res.status(400).json({
        error: "Enter a valid transaction reference."
      });
    }

    // Verify that the selected method exists and is active.
    const methodResult = await pool.query(
      `SELECT id, method_name, currency
       FROM payment_settings
       WHERE id = $1 AND is_active = TRUE`,
      [methodId]
    );

    if (methodResult.rows.length === 0) {
      return res.status(400).json({
        error: "Selected payment method is unavailable."
      });
    }

    const paymentMethod = methodResult.rows[0];

    if (paymentMethod.currency !== depositCurrency) {
      return res.status(400).json({
        error: "Payment method currency does not match deposit currency."
      });
    }

    const result = await pool.query(
      `INSERT INTO deposit_requests
       (
         user_id,
         amount,
         currency,
         payment_method_id,
         transaction_reference,
         note,
         status
       )
       VALUES ($1, $2, $3, $4, $5, $6, 'pending')
       RETURNING id, amount, currency,
                 payment_method_id,
                 transaction_reference,
                 note, status, created_at`,
      [
        userId,
        depositAmount.toFixed(2),
        depositCurrency,
        methodId,
        reference,
        cleanNote
      ]
    );

    res.status(201).json({
      success: true,
      message: "Deposit request submitted. Waiting for admin approval.",
      deposit: {
        ...result.rows[0],
        payment_method_name: paymentMethod.method_name
      }
    });

  } catch (error) {
    console.error("Deposit request error:", error);

    res.status(500).json({
      error: "Could not submit deposit request."
    });
  }
});
    



// ========================================
// USER DEPOSIT HISTORY
// ========================================

app.get("/api/deposits/mine", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         d.id,
         d.amount,
         d.currency,
         d.transaction_reference,
         d.note,
         d.status,
         d.created_at,
         d.reviewed_at,
         p.method_name AS payment_method_name
       FROM deposit_requests d
       LEFT JOIN payment_settings p
         ON p.id = d.payment_method_id
       WHERE d.user_id = $1
       ORDER BY d.created_at DESC
       LIMIT 100`,
      [req.session.user.id]
    );

    res.json({
      deposits: result.rows
    });

  } catch (error) {
    console.error("Deposit history error:", error);

    res.status(500).json({
      error: "Could not load deposit history."
    });
  }
});


// ========================================
// USER WALLET TRANSACTION HISTORY
// ========================================

app.get(
  "/api/wallet/transactions",
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, amount, currency,
                transaction_type, description,
                reference_id, created_at
         FROM wallet_transactions
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 100`,
        [req.session.user.id]
      );

      res.json({
        transactions: result.rows
      });

    } catch (error) {
      console.error("Wallet transactions error:", error);

      res.status(500).json({
        error: "Could not load wallet transactions."
      });
    }
  }
);
// ========================================
// ADMIN: VIEW ALL DEPOSIT REQUESTS
// ========================================

app.get(
  "/api/admin/deposits",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
  d.id,
  d.user_id,
  u.full_name,
  u.email,
  d.amount,
  d.currency,
  d.payment_method_id,
  p.method_name AS payment_method_name,
  p.account_name AS payment_account_name,
  d.transaction_reference,
  d.receipt_url,
  d.note,
  d.status,
  d.created_at,
  d.reviewed_at
FROM deposit_requests d
JOIN app_users u ON u.id = d.user_id
LEFT JOIN payment_settings p
  ON p.id = d.payment_method_id
ORDER BY
  CASE WHEN d.status = 'pending' THEN 0 ELSE 1 END,
   d.created_at DESC
LIMIT 200`
      );

      res.json({
        deposits: result.rows
      });

    } catch (error) {
      console.error("Admin deposits error:", error);

      res.status(500).json({
        error: "Could not load deposit requests."
      });
    }
  }
);


// ========================================
// ADMIN: CONFIRM OR REJECT DEPOSIT
// ========================================

app.patch(
  "/api/admin/deposits/:id/status",
  requireAdmin,
  async (req, res) => {
    const depositId = Number(req.params.id);
    const { status } = req.body;

    if (
      !Number.isSafeInteger(depositId) ||
      depositId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid deposit ID."
      });
    }

    if (!["confirmed", "rejected"].includes(status)) {
      return res.status(400).json({
        error: "Status must be confirmed or rejected."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Lock the deposit to prevent duplicate approval.
      const depositResult = await client.query(
        `SELECT *
         FROM deposit_requests
         WHERE id = $1
         FOR UPDATE`,
        [depositId]
      );

      if (depositResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Deposit request not found."
        });
      }

      const deposit = depositResult.rows[0];

      if (deposit.status !== "pending") {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "This deposit has already been reviewed."
        });
      }

      // This demo wallet supports USD credit only.
      if (
        status === "confirmed" &&
        deposit.currency !== "USD"
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Only USD deposits can currently be credited. ETB conversion is not configured."
        });
      }

      if (status === "confirmed") {
        // Create wallet if it does not exist.
        await client.query(
          `INSERT INTO wallet_accounts
           (user_id, currency, balance)
           VALUES ($1, 'USD', 0)
           ON CONFLICT (user_id, currency)
           DO NOTHING`,
          [deposit.user_id]
        );

        // Credit the wallet exactly once.
        await client.query(
          `UPDATE wallet_accounts
           SET balance = balance + $1
           WHERE user_id = $2
           AND currency = 'USD'`,
          [deposit.amount, deposit.user_id]
        );

        // Record the wallet transaction.
        await client.query(
          `INSERT INTO wallet_transactions
           (user_id, amount, currency,
            transaction_type, description, reference_id)
           VALUES ($1, $2, 'USD', 'deposit',
                   $3, $4)`,
          [
            deposit.user_id,
            deposit.amount,
            `Admin-approved deposit #${deposit.id}`,
            deposit.id
          ]
        );
      }

      // Update deposit status.
      await client.query(
        `UPDATE deposit_requests
         SET status = $1,
             reviewed_at = NOW()
         WHERE id = $2`,
        [status, depositId]
      );

      // Notify the user.
      const notificationTitle =
        status === "confirmed"
          ? "Deposit Approved"
          : "Deposit Rejected";

      const notificationMessage =
        status === "confirmed"
          ? `Your USD deposit of ${deposit.amount} USD has been approved and credited to your demo wallet.`
          : `Your deposit request #${deposit.id} was rejected. Please contact support if you need help.`;

      await client.query(
        `INSERT INTO user_notifications
         (user_id, title, message)
         VALUES ($1, $2, $3)`,
        [
          deposit.user_id,
          notificationTitle,
          notificationMessage
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          status === "confirmed"
            ? "Deposit confirmed and USD wallet credited."
            : "Deposit rejected successfully.",
        depositId,
        status
      });

    } catch (error) {
      await client.query("ROLLBACK");

      console.error("Deposit review error:", error);

      res.status(500).json({
        error: "Could not review deposit."
      });

    } finally {
      client.release();
    }
  }
);
// ========================================
// USER: GET NOTIFICATIONS
// ========================================

app.get(
  "/api/notifications",
  requireLogin,
  async (req, res) => {
    try {
      const userId = req.session.user.id;

      const result = await pool.query(
        `SELECT id, title, message, is_read, created_at
         FROM user_notifications
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 100`,
        [userId]
      );

      const unreadResult = await pool.query(
        `SELECT COUNT(*) AS unread_count
         FROM user_notifications
         WHERE user_id = $1 AND is_read = FALSE`,
        [userId]
      );

      res.json({
        notifications: result.rows,
        unreadCount: Number(unreadResult.rows[0].unread_count)
      });

    } catch (error) {
      console.error("Notifications error:", error);

      res.status(500).json({
        error: "Could not load notifications."
      });
    }
  }
);


// ========================================
// USER: MARK ONE NOTIFICATION AS READ
// ========================================

app.patch(
  "/api/notifications/:id/read",
  requireLogin,
  async (req, res) => {
    try {
      const notificationId = Number(req.params.id);

      if (
        !Number.isSafeInteger(notificationId) ||
        notificationId <= 0
      ) {
        return res.status(400).json({
          error: "Invalid notification ID."
        });
      }

      const result = await pool.query(
        `UPDATE user_notifications
         SET is_read = TRUE
         WHERE id = $1 AND user_id = $2
         RETURNING id, is_read`,
        [
          notificationId,
          req.session.user.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Notification not found."
        });
      }

      res.json({
        success: true,
        message: "Notification marked as read."
      });

    } catch (error) {
      console.error("Mark notification error:", error);

      res.status(500).json({
        error: "Could not update notification."
      });
    }
  }
);


// ========================================
// USER: MARK ALL NOTIFICATIONS AS READ
// ========================================

app.patch(
  "/api/notifications/read-all",
  requireLogin,
  async (req, res) => {
    try {
      await pool.query(
        `UPDATE user_notifications
         SET is_read = TRUE
         WHERE user_id = $1 AND is_read = FALSE`,
        [req.session.user.id]
      );

      res.json({
        success: true,
        message: "All notifications marked as read."
      });

    } catch (error) {
      console.error("Read all notifications error:", error);

      res.status(500).json({
        error: "Could not update notifications."
      });
    }
  }
);
// ========================================
// USER: GET MY SUPPORT MESSAGES
// ========================================

app.get(
  "/api/support/messages",
  requireLogin,
  async (req, res) => {
    try {
      const userId = req.session.user.id;

      // Mark admin replies as read when user opens chat.
      await pool.query(
        `UPDATE support_messages
         SET is_read = TRUE
         WHERE user_id = $1
           AND sender_role = 'admin'
           AND is_read = FALSE`,
        [userId]
      );

      const result = await pool.query(
        `SELECT id, sender_role, message,
                is_read, created_at
         FROM support_messages
         WHERE user_id = $1
         ORDER BY created_at ASC
         LIMIT 300`,
        [userId]
      );

      res.json({
        messages: result.rows
      });

    } catch (error) {
      console.error("User support messages error:", error);

      res.status(500).json({
        error: "Could not load support messages."
      });
    }
  }
);


// ========================================
// USER: SEND MESSAGE TO ADMIN
// ========================================

app.post(
  "/api/support/messages",
  requireLogin,
  async (req, res) => {
    try {
      const userId = req.session.user.id;
      const { message } = req.body;

      if (typeof message !== "string") {
        return res.status(400).json({
          error: "Message is required."
        });
      }

      const cleanMessage = message.trim();

      if (!cleanMessage || cleanMessage.length > 2000) {
        return res.status(400).json({
          error: "Message must contain 1–2000 characters."
        });
      }

      const result = await pool.query(
        `INSERT INTO support_messages
         (user_id, sender_role, message)
         VALUES ($1, 'user', $2)
         RETURNING id, sender_role, message,
                   is_read, created_at`,
        [userId, cleanMessage]
      );

      res.status(201).json({
        success: true,
        message: "Message sent successfully.",
        data: result.rows[0]
      });

    } catch (error) {
      console.error("Send support message error:", error);

      res.status(500).json({
        error: "Could not send message."
      });
    }
  }
);


// ========================================
// ADMIN: GET SUPPORT CONVERSATIONS
// ========================================

app.get(
  "/api/admin/support/conversations",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           u.id AS user_id,
           u.full_name,
           u.email,
           latest.message AS last_message,
           latest.sender_role AS last_sender,
           latest.created_at AS last_message_at,
           COALESCE(unread.unread_count, 0)::INTEGER
             AS unread_count
         FROM app_users u

         JOIN LATERAL (
           SELECT message, sender_role, created_at
           FROM support_messages
           WHERE user_id = u.id
           ORDER BY created_at DESC, id DESC
           LIMIT 1
         ) latest ON TRUE

         LEFT JOIN LATERAL (
           SELECT COUNT(*) AS unread_count
           FROM support_messages
           WHERE user_id = u.id
             AND sender_role = 'user'
             AND is_read = FALSE
         ) unread ON TRUE

         ORDER BY latest.created_at DESC
         LIMIT 200`
      );

      res.json({
        conversations: result.rows
      });

    } catch (error) {
      console.error("Admin conversations error:", error);

      res.status(500).json({
        error: "Could not load conversations."
      });
    }
  }
);


// ========================================
// ADMIN: GET ONE USER CONVERSATION
// ========================================

app.get(
  "/api/admin/support/:userId/messages",
  requireAdmin,
  async (req, res) => {
    try {
      const userId = Number(req.params.userId);

      if (
        !Number.isSafeInteger(userId) ||
        userId <= 0
      ) {
        return res.status(400).json({
          error: "Invalid user ID."
        });
      }

      const userResult = await pool.query(
        `SELECT id, full_name, email
         FROM app_users
         WHERE id = $1`,
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      // Mark user's messages as read.
      await pool.query(
        `UPDATE support_messages
         SET is_read = TRUE
         WHERE user_id = $1
           AND sender_role = 'user'
           AND is_read = FALSE`,
        [userId]
      );

      const messagesResult = await pool.query(
        `SELECT id, sender_role, message,
                is_read, created_at
         FROM support_messages
         WHERE user_id = $1
         ORDER BY created_at ASC
         LIMIT 300`,
        [userId]
      );

      res.json({
        user: userResult.rows[0],
        messages: messagesResult.rows
      });

    } catch (error) {
      console.error("Admin conversation error:", error);

      res.status(500).json({
        error: "Could not load conversation."
      });
    }
  }
);


// ========================================
// ADMIN: REPLY TO USER
// ========================================

app.post(
  "/api/admin/support/:userId/reply",
  requireAdmin,
  async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const { message } = req.body;

      if (
        !Number.isSafeInteger(userId) ||
        userId <= 0
      ) {
        return res.status(400).json({
          error: "Invalid user ID."
        });
      }

      if (typeof message !== "string") {
        return res.status(400).json({
          error: "Reply message is required."
        });
      }

      const cleanMessage = message.trim();

      if (!cleanMessage || cleanMessage.length > 2000) {
        return res.status(400).json({
          error: "Reply must contain 1–2000 characters."
        });
      }

      const userResult = await pool.query(
        "SELECT id FROM app_users WHERE id = $1",
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      const result = await pool.query(
        `INSERT INTO support_messages
         (user_id, sender_role, message)
         VALUES ($1, 'admin', $2)
         RETURNING id, sender_role, message,
                   is_read, created_at`,
        [userId, cleanMessage]
      );

      await pool.query(
        `INSERT INTO user_notifications
         (user_id, title, message)
         VALUES ($1, $2, $3)`,
        [
          userId,
          "New Support Reply",
          "Admin has replied to your support message."
        ]
      );

      res.status(201).json({
        success: true,
        message: "Reply sent successfully.",
        data: result.rows[0]
      });

    } catch (error) {
      console.error("Admin support reply error:", error);

      res.status(500).json({
        error: "Could not send reply."
      });
    }
  }
);
// ========================================
// TRANSFER TABLE: ADD EXTRA COLUMNS
// ========================================

async function initializeTransferColumns() {
  await pool.query(`
    ALTER TABLE transfer_requests
      ADD COLUMN IF NOT EXISTS recipient_name VARCHAR(150),
      ADD COLUMN IF NOT EXISTS recipient_contact VARCHAR(150),
      ADD COLUMN IF NOT EXISTS payout_method VARCHAR(100),
      ADD COLUMN IF NOT EXISTS note VARCHAR(300)
  `);
}


// ========================================
// USER: CREATE SEND MONEY REQUEST
// ========================================

app.post(
  "/api/transfers",
  requireLogin,
  async (req, res) => {
    try {
      const userId = req.session.user.id;

      const {
        amount,
        recipient_name,
        recipient_contact,
        payout_method,
        note
      } = req.body;

      const transferAmount = Number(amount);

      const recipientName =
        typeof recipient_name === "string"
          ? recipient_name.trim()
          : "";

      const recipientContact =
        typeof recipient_contact === "string"
          ? recipient_contact.trim()
          : "";

      const payoutMethod =
        typeof payout_method === "string"
          ? payout_method.trim()
          : "";

      const transferNote =
        typeof note === "string"
          ? note.trim().slice(0, 300)
          : "";

      if (
        !Number.isFinite(transferAmount) ||
        transferAmount <= 0 ||
        transferAmount > 1000000
      ) {
        return res.status(400).json({
          error: "Enter a valid transfer amount."
        });
      }

      if (
        recipientName.length < 2 ||
        recipientName.length > 150
      ) {
        return res.status(400).json({
          error: "Enter a valid recipient name."
        });
      }

      if (
        recipientContact.length < 3 ||
        recipientContact.length > 150
      ) {
        return res.status(400).json({
          error: "Enter a valid recipient contact."
        });
      }

      const allowedMethods = [
        "Commercial Bank of Ethiopia",
        "Telebirr",
        "Bank of Abyssinia",
        "Awash Bank",
        "Dashen Bank"
      ];

      if (!allowedMethods.includes(payoutMethod)) {
        return res.status(400).json({
          error: "Select a supported payout method."
        });
      }

      // This is a demo request, not a real money transfer.
      const result = await pool.query(
        `INSERT INTO transfer_requests
         (
           user_id,
           amount,
           currency,
           recipient_name,
           recipient_contact,
           payout_method,
           note,
           status
         )
         VALUES ($1, $2, 'USD', $3, $4, $5, $6, 'pending')
         RETURNING *`,
        [
          userId,
          transferAmount.toFixed(2),
          recipientName,
          recipientContact,
          payoutMethod,
          transferNote
        ]
      );

      res.status(201).json({
        success: true,
        message: "Demo transfer request submitted for review.",
        transfer: result.rows[0]
      });

    } catch (error) {
      console.error("Create transfer error:", error);

      res.status(500).json({
        error: "Could not submit transfer request."
      });
    }
  }
);


// ========================================
// USER: VIEW MY TRANSFER REQUESTS
// ========================================

app.get(
  "/api/transfers/mine",
  requireLogin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           id,
           amount,
           currency,
           recipient_name,
           recipient_contact,
           payout_method,
           note,
           status,
           created_at,
           reviewed_at
         FROM transfer_requests
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 100`,
        [req.session.user.id]
      );

      res.json({
        transfers: result.rows
      });

    } catch (error) {
      console.error("User transfers error:", error);

      res.status(500).json({
        error: "Could not load transfer history."
      });
    }
  }
);


// ========================================
// ADMIN: VIEW ALL TRANSFER REQUESTS
// ========================================

app.get(
  "/api/admin/transfers",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
           t.id,
           t.user_id,
           u.full_name,
           u.email,
           t.amount,
           t.currency,
           t.recipient_name,
           t.recipient_contact,
           t.payout_method,
           t.note,
           t.status,
           t.created_at,
           t.reviewed_at
         FROM transfer_requests t
         JOIN app_users u ON u.id = t.user_id
         ORDER BY
           CASE WHEN t.status = 'pending' THEN 0 ELSE 1 END,
           t.created_at DESC
         LIMIT 200`
      );

      res.json({
        transfers: result.rows
      });

    } catch (error) {
      console.error("Admin transfers error:", error);

      res.status(500).json({
        error: "Could not load transfer requests."
      });
    }
  }
);


// ========================================
// ADMIN: CONFIRM OR REJECT TRANSFER REQUEST
// ========================================

app.patch(
  "/api/admin/transfers/:id/status",
  requireAdmin,
  async (req, res) => {
    const transferId = Number(req.params.id);
    const { status } = req.body;

    if (
      !Number.isSafeInteger(transferId) ||
      transferId <= 0
    ) {
      return res.status(400).json({
        error: "Invalid transfer ID."
      });
    }

    if (!["confirmed", "rejected"].includes(status)) {
      return res.status(400).json({
        error: "Status must be confirmed or rejected."
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const transferResult = await client.query(
        `SELECT *
         FROM transfer_requests
         WHERE id = $1
         FOR UPDATE`,
        [transferId]
      );

      if (transferResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Transfer request not found."
        });
      }

      const transfer = transferResult.rows[0];

      if (transfer.status !== "pending") {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "This request has already been reviewed."
        });
      }

      await client.query(
        `UPDATE transfer_requests
         SET status = $1,
             reviewed_at = NOW()
         WHERE id = $2`,
        [status, transferId]
      );

      await client.query(
        `INSERT INTO user_notifications
         (user_id, title, message)
         VALUES ($1, $2, $3)`,
        [
          transfer.user_id,
          status === "confirmed"
            ? "Transfer Request Reviewed"
            : "Transfer Request Rejected",
          status === "confirmed"
            ? `Your demo transfer request #${transferId} has been reviewed and approved. This does not mean money was sent.`
            : `Your demo transfer request #${transferId} was rejected. Please contact support if you need help.`
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          status === "confirmed"
            ? "Demo transfer request approved."
            : "Transfer request rejected.",
        transferId,
        status
      });

    } catch (error) {
      await client.query("ROLLBACK");

      console.error("Admin transfer review error:", error);

      res.status(500).json({
        error: "Could not review transfer request."
      });

    } finally {
      client.release();
    }
  }
);
// ========================================
// ADMIN: VIEW ALL PAYMENT METHODS
// ========================================

app.get(
  "/api/admin/payment-methods",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, method_name, account_name,
                account_number, payment_link,
                instructions, currency, is_active,
                created_at
         FROM payment_settings
         ORDER BY created_at DESC`
      );

      res.json({
        paymentMethods: result.rows
      });

    } catch (error) {
      console.error("Admin payment methods error:", error);

      res.status(500).json({
        error: "Could not load payment methods."
      });
    }
  }
);


// ========================================
// ADMIN: ADD PAYMENT METHOD
// ========================================

app.post(
  "/api/admin/payment-methods",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        method_name,
        account_name,
        account_number,
        payment_link,
        instructions,
        currency
      } = req.body;

      if (
        typeof method_name !== "string" ||
        method_name.trim().length < 2 ||
        method_name.trim().length > 100
      ) {
        return res.status(400).json({
          error: "Enter a valid payment method name."
        });
      }

      const cleanCurrency =
        typeof currency === "string"
          ? currency.trim().toUpperCase()
          : "USD";

      if (!["USD", "ETB"].includes(cleanCurrency)) {
        return res.status(400).json({
          error: "Currency must be USD or ETB."
        });
      }

      const cleanAccountName =
        typeof account_name === "string"
          ? account_name.trim().slice(0, 150)
          : null;

      const cleanAccountNumber =
        typeof account_number === "string"
          ? account_number.trim().slice(0, 150)
          : null;

      const cleanPaymentLink =
        typeof payment_link === "string"
          ? payment_link.trim().slice(0, 1000)
          : null;

      if (cleanPaymentLink) {
        let parsedLink;

        try {
          parsedLink = new URL(cleanPaymentLink);
        } catch {
          return res.status(400).json({
            error: "Payment link must be a valid URL."
          });
        }

        if (!["https:", "http:"].includes(parsedLink.protocol)) {
          return res.status(400).json({
            error: "Invalid payment link protocol."
          });
        }
      }

      const cleanInstructions =
        typeof instructions === "string"
          ? instructions.trim().slice(0, 2000)
          : null;

      const result = await pool.query(
        `INSERT INTO payment_settings
         (
           method_name,
           account_name,
           account_number,
           payment_link,
           instructions,
           currency,
           is_active
         )
         VALUES ($1, $2, $3, $4, $5, $6, TRUE)
         RETURNING *`,
        [
          method_name.trim(),
          cleanAccountName,
          cleanAccountNumber,
          cleanPaymentLink,
          cleanInstructions,
          cleanCurrency
        ]
      );

      res.status(201).json({
        success: true,
        message: "Payment method added successfully.",
        paymentMethod: result.rows[0]
      });

    } catch (error) {
      console.error("Add payment method error:", error);

      res.status(500).json({
        error: "Could not add payment method."
      });
    }
  }
);


// ========================================
// ADMIN: UPDATE PAYMENT METHOD
// ========================================

app.patch(
  "/api/admin/payment-methods/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "Invalid payment method ID."
        });
      }

      const {
        method_name,
        account_name,
        account_number,
        payment_link,
        instructions,
        currency,
        is_active
      } = req.body;

      if (
        typeof method_name !== "string" ||
        method_name.trim().length < 2 ||
        method_name.trim().length > 100
      ) {
        return res.status(400).json({
          error: "Enter a valid payment method name."
        });
      }

      const cleanCurrency =
        typeof currency === "string"
          ? currency.trim().toUpperCase()
          : "";

      if (!["USD", "ETB"].includes(cleanCurrency)) {
        return res.status(400).json({
          error: "Currency must be USD or ETB."
        });
      }

      if (typeof is_active !== "boolean") {
        return res.status(400).json({
          error: "is_active must be true or false."
        });
      }

      const cleanLink =
        typeof payment_link === "string"
          ? payment_link.trim().slice(0, 1000)
          : null;

      if (cleanLink) {
        let parsedLink;

        try {
          parsedLink = new URL(cleanLink);
        } catch {
          return res.status(400).json({
            error: "Payment link must be a valid URL."
          });
        }

        if (!["https:", "http:"].includes(parsedLink.protocol)) {
          return res.status(400).json({
            error: "Invalid payment link protocol."
          });
        }
      }

      const result = await pool.query(
        `UPDATE payment_settings
         SET method_name = $1,
             account_name = $2,
             account_number = $3,
             payment_link = $4,
             instructions = $5,
             currency = $6,
             is_active = $7
         WHERE id = $8
         RETURNING *`,
        [
          method_name.trim(),
          typeof account_name === "string"
            ? account_name.trim().slice(0, 150)
            : null,
          typeof account_number === "string"
            ? account_number.trim().slice(0, 150)
            : null,
          cleanLink,
          typeof instructions === "string"
            ? instructions.trim().slice(0, 2000)
            : null,
          cleanCurrency,
          is_active,
          id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Payment method not found."
        });
      }

      res.json({
        success: true,
        message: "Payment method updated.",
        paymentMethod: result.rows[0]
      });

    } catch (error) {
      console.error("Update payment method error:", error);

      res.status(500).json({
        error: "Could not update payment method."
      });
    }
  }
);


// ========================================
// ADMIN: DELETE PAYMENT METHOD
// ========================================

app.delete(
  "/api/admin/payment-methods/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "Invalid payment method ID."
        });
      }

      const result = await pool.query(
        `DELETE FROM payment_settings
         WHERE id = $1
         RETURNING id`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Payment method not found."
        });
      }

      res.json({
        success: true,
        message: "Payment method deleted."
      });

    } catch (error) {
      console.error("Delete payment method error:", error);

      res.status(500).json({
        error: "Could not delete payment method."
      });
    }
  }
);
// ========================================
// ADMIN: DASHBOARD SUMMARY
// ========================================

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  async (req, res) => {
    try {
      const [
        usersResult,
        depositsResult,
        transfersResult,
        walletResult,
        supportResult,
        recentDepositsResult,
        recentTransfersResult
      ] = await Promise.all([

        // Total users
        pool.query(`
          SELECT COUNT(*) AS total_users
          FROM app_users
          WHERE role = 'user'
        `),

        // Deposit statistics
        pool.query(`
          SELECT
            COUNT(*) FILTER (
              WHERE status = 'pending'
            ) AS pending_deposits,

            COUNT(*) FILTER (
              WHERE status = 'confirmed'
            ) AS confirmed_deposits,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            ) AS rejected_deposits
          FROM deposit_requests
        `),

        // Transfer statistics
        pool.query(`
          SELECT
            COUNT(*) FILTER (
              WHERE status = 'pending'
            ) AS pending_transfers,

            COUNT(*) FILTER (
              WHERE status = 'confirmed'
            ) AS confirmed_transfers,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            ) AS rejected_transfers
          FROM transfer_requests
        `),

        // USD wallet summary
        pool.query(`
          SELECT
            COUNT(*) AS wallet_count,
            COALESCE(SUM(balance), 0) AS total_usd_balance
          FROM wallet_accounts
          WHERE currency = 'USD'
        `),

        // Unread support messages
        pool.query(`
          SELECT COUNT(*) AS unread_support_messages
          FROM support_messages
          WHERE sender_role = 'user'
          AND is_read = FALSE
        `),

        // Recent deposits
        pool.query(`
          SELECT
            d.id,
            d.user_id,
            u.full_name,
            d.amount,
            d.currency,
            d.status,
            d.created_at
          FROM deposit_requests d
          JOIN app_users u ON u.id = d.user_id
          ORDER BY d.created_at DESC
          LIMIT 5
        `),

        // Recent transfers
        pool.query(`
          SELECT
            t.id,
            t.user_id,
            u.full_name,
            t.amount,
            t.currency,
            t.recipient_name,
            t.status,
            t.created_at
          FROM transfer_requests t
          JOIN app_users u ON u.id = t.user_id
          ORDER BY t.created_at DESC
          LIMIT 5
        `)
      ]);

      res.json({
        success: true,

        users: {
          total: Number(
            usersResult.rows[0].total_users
          )
        },

        deposits: {
          pending: Number(
            depositsResult.rows[0].pending_deposits
          ),
          confirmed: Number(
            depositsResult.rows[0].confirmed_deposits
          ),
          rejected: Number(
            depositsResult.rows[0].rejected_deposits
          )
        },

        transfers: {
          pending: Number(
            transfersResult.rows[0].pending_transfers
          ),
          confirmed: Number(
            transfersResult.rows[0].confirmed_transfers
          ),
          rejected: Number(
            transfersResult.rows[0].rejected_transfers
          )
        },

        wallet: {
          count: Number(
            walletResult.rows[0].wallet_count
          ),
          totalUsdBalance: Number(
            walletResult.rows[0].total_usd_balance
          )
        },

        support: {
          unreadMessages: Number(
            supportResult.rows[0].unread_support_messages
          )
        },

        recentDeposits: recentDepositsResult.rows,
        recentTransfers: recentTransfersResult.rows
      });

    } catch (error) {
      console.error("Admin dashboard error:", error);

      res.status(500).json({
        error: "Could not load admin dashboard."
      });
    }
  }
);
// ========================================
// USER: GET PROFILE
// ========================================

app.get("/api/profile", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         id,
         full_name,
         email,
         first_name,
         last_name,
         country,
         role,
         created_at
       FROM app_users
       WHERE id = $1`,
      [req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User account not found."
      });
    }

    res.json({
      success: true,
      profile: result.rows[0]
    });

  } catch (error) {
    console.error("Get profile error:", error);

    res.status(500).json({
      error: "Could not load profile."
    });
  }
});


// ========================================
// USER: UPDATE PROFILE
// ========================================

app.patch("/api/profile", requireLogin, async (req, res) => {
  try {
    const { full_name, first_name, last_name, country } = req.body;

    if (
      typeof full_name !== "string" ||
      full_name.trim().length < 2 ||
      full_name.trim().length > 120
    ) {
      return res.status(400).json({
        error: "Full name must contain 2–120 characters."
      });
    }

    const cleanFirstName =
      typeof first_name === "string"
        ? first_name.trim().slice(0, 60)
        : null;

    const cleanLastName =
      typeof last_name === "string"
        ? last_name.trim().slice(0, 60)
        : null;

    const cleanCountry =
      typeof country === "string"
        ? country.trim().slice(0, 100)
        : null;

    const result = await pool.query(
      `UPDATE app_users
       SET full_name = $1,
           first_name = $2,
           last_name = $3,
           country = $4
       WHERE id = $5
       RETURNING
         id, full_name, email,
         first_name, last_name,
         country, role, created_at`,
      [
        full_name.trim(),
        cleanFirstName,
        cleanLastName,
        cleanCountry,
        req.session.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User account not found."
      });
    }

    const updatedUser = result.rows[0];

    // Update the current session name.
    req.session.user.fullName = updatedUser.full_name;

    await saveSession(req);

    res.json({
      success: true,
      message: "Profile updated successfully.",
      profile: updatedUser
    });

  } catch (error) {
    console.error("Update profile error:", error);

    res.status(500).json({
      error: "Could not update profile."
    });
  }
});


// ========================================
// USER: CHANGE PASSWORD
// ========================================

app.patch(
  "/api/profile/password",
  requireLogin,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;

      if (
        typeof currentPassword !== "string" ||
        typeof newPassword !== "string"
      ) {
        return res.status(400).json({
          error: "Current and new passwords are required."
        });
      }

      if (
        newPassword.length < 8 ||
        newPassword.length > 128
      ) {
        return res.status(400).json({
          error: "New password must contain 8–128 characters."
        });
      }

      const result = await pool.query(
        `SELECT password_hash
         FROM app_users
         WHERE id = $1`,
        [req.session.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Account not found."
        });
      }

      const passwordHash = result.rows[0].password_hash;

      if (!passwordHash) {
        return res.status(400).json({
          error: "This account uses Google Login. Password change is unavailable."
        });
      }

      const validPassword = await bcrypt.compare(
        currentPassword,
        passwordHash
      );

      if (!validPassword) {
        return res.status(401).json({
          error: "Current password is incorrect."
        });
      }

      const newHash = await bcrypt.hash(newPassword, 12);

      await pool.query(
        `UPDATE app_users
         SET password_hash = $1
         WHERE id = $2`,
        [newHash, req.session.user.id]
      );

      res.json({
        success: true,
        message: "Password changed successfully."
      });

    } catch (error) {
      console.error("Change password error:", error);

      res.status(500).json({
        error: "Could not change password."
      });
    }
  }
);
// ========================================
// USER HOME PAGE
// ========================================

app.get("/", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  if (req.session.user.role === "admin") {
    return res.redirect("/admin");
  }

  return res.sendFile(
    path.join(__dirname, "index.html")
  );
});


// ========================================
// LOGIN PAGE
// ========================================

app.get("/login.html", (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === "admin") {
      return res.redirect("/admin");
    }

    return res.redirect("/");
  }

  res.sendFile(
    path.join(__dirname, "login.html")
  );
});


// ========================================
// ADMIN PAGE
// ========================================

app.get("/admin", requireLogin, requireAdmin, (req, res) => {
  res.sendFile(
    path.join(__dirname, "admin.html")
  );
});
// ABYSSINIASEND LOGO
app.get("/logo.png", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "AbyssiniaSend Global Transfer Logo.png"
    )
  );
});

// ========================================
// STATIC ASSETS
// ========================================

// Keep CSS, JavaScript and image assets in a public folder.
app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


// ========================================
// API 404 HANDLER
// ========================================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found."
  });
});


// ========================================
// GENERAL ERROR HANDLER
// ========================================

app.use((err, req, res, next) => {
  console.error("Server error:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "An internal server error occurred."
  });
});


// ========================================
// START SERVER
// ========================================

async function start() {
  try {
    await initializeDatabase();

    await initializeTransferColumns();

    const server = app.listen(PORT, () => {
      console.log(
        `AbyssiniaSend server running on port ${PORT}`
      );
    });

    server.on("error", (error) => {
      console.error("Server startup error:", error);
      process.exit(1);
    });

  } catch (error) {
    console.error(
      "Failed to initialize AbyssiniaSend:",
      error
    );

    process.exit(1);
  }
}

start();
