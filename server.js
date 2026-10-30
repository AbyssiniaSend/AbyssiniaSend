
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
  // Add registration fields without deleting existing users
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
  
  // Admin-managed payment instructions
  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_settings (
      id BIGSERIAL PRIMARY KEY,
      method_name VARCHAR(80) NOT NULL,
      account_name VARCHAR(120) NOT NULL,
      account_number VARCHAR(120),
      payment_link TEXT,
      instructions TEXT,
      currency VARCHAR(3) NOT NULL DEFAULT 'USD',
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Extend deposit requests safely
  await pool.query(`
    ALTER TABLE deposit_requests
      ADD COLUMN IF NOT EXISTS transaction_reference VARCHAR(120),
      ADD COLUMN IF NOT EXISTS receipt_url TEXT
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
/* Serve the brand logo only */
app.get("/logo.png", (req, res) => {
  res.sendFile(
    path.join(__dirname, "AbyssiniaSend Global Transfer Logo.png"),
    (error) => {
      if (error) {
        console.error("Logo file error:", error.message);

        if (!res.headersSent) {
          res.status(404).send("Logo file not found on server.");
        }
      }
    }
  );
});
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
    const {
      firstName,
      lastName,
      country,
      email,
      password,
      confirmPassword
    } = req.body || {};

    if (
      [firstName, lastName, country, email, password, confirmPassword]
        .some(value => typeof value !== "string")
    ) {
      return res.status(400).json({
        error: "Complete all registration fields."
      });
    }

    const cleanFirstName = firstName.trim();
    const cleanLastName = lastName.trim();
    const cleanCountry = country.trim().toUpperCase();
    const cleanName = `${cleanFirstName} ${cleanLastName}`;
    const cleanEmail = email.trim().toLowerCase();

    const allowedCountries = new Set([
      "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR",
      "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE",
      "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
      "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD",
      "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR",
      "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
      "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
      "FJ", "FK", "FM", "FO", "FR", "GA", "GD", "GE", "GF", "GG",
      "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT",
      "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID",
      "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE",
      "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP",
      "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR",
      "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF",
      "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR",
      "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC",
      "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
      "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN",
      "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU",
      "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ",
      "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX",
      "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
      "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG",
      "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN",
      "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
    ]);

    if (
      cleanFirstName.length < 1 ||
      cleanFirstName.length > 60 ||
      cleanLastName.length < 1 ||
      cleanLastName.length > 60 ||
      cleanName.length > 120 ||
      !allowedCountries.has(cleanCountry) ||
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Check your name, country, email and password requirements."
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        error: "Passwords do not match."
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
        (full_name, first_name, last_name, country, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5, $6, 'user')
       ON CONFLICT (email) DO NOTHING
       RETURNING id, full_name, email, role`,
      [
        cleanName,
        cleanFirstName,
        cleanLastName,
        cleanCountry,
        cleanEmail,
        passwordHash
      ]
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
app.post("/api/login", loginLimiter, async (req, res, next) => {
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

/* Get active payment methods: signed-in users */
app.get("/api/payment-methods", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, method_name, account_name, account_number,
             payment_link, instructions, currency
      FROM payment_settings
      WHERE is_active = TRUE
      ORDER BY id ASC
    `);

    res.set("Cache-Control", "no-store");
    return res.json({ paymentMethods: result.rows });
  } catch (error) {
    next(error);
  }
});

/* Add payment method: administrator only */
app.post("/api/admin/payment-methods", requireAdmin, async (req, res, next) => {
  try {
    const {
      method_name,
      account_name,
      account_number,
      payment_link,
      instructions,
      currency
    } = req.body || {};

    if (
      typeof method_name !== "string" ||
      typeof account_name !== "string" ||
      !method_name.trim() ||
      !account_name.trim()
    ) {
      return res.status(400).json({
        error: "Payment method and account name are required."
      });
    }

    const cleanCurrency = currency || "USD";

    if (!["USD", "ETB"].includes(cleanCurrency)) {
      return res.status(400).json({
        error: "Currency must be USD or ETB."
      });
    }

    if (
      payment_link &&
      (typeof payment_link !== "string" ||
       !/^https:\/\//i.test(payment_link))
    ) {
      return res.status(400).json({
        error: "Payment link must use HTTPS."
      });
    }

    const result = await pool.query(
      `INSERT INTO payment_settings
       (method_name, account_name, account_number,
        payment_link, instructions, currency)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        method_name.trim(),
        account_name.trim(),
        account_number || null,
        payment_link || null,
        instructions || null,
        cleanCurrency
      ]
    );

    return res.status(201).json({
      message: "Payment method added.",
      paymentMethod: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

/* Update or deactivate payment method: administrator only */
app.patch(
  "/api/admin/payment-methods/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const {
        method_name,
        account_name,
        account_number,
        payment_link,
        instructions,
        currency,
        is_active
      } = req.body || {};

      if (!/^[1-9]\d*$/.test(id)) {
        return res.status(400).json({
          error: "Invalid payment method ID."
        });
      }

      if (currency !== undefined &&
          !["USD", "ETB"].includes(currency)) {
        return res.status(400).json({
          error: "Currency must be USD or ETB."
        });
      }

      if (
        payment_link &&
        (typeof payment_link !== "string" ||
         !/^https:\/\//i.test(payment_link))
      ) {
        return res.status(400).json({
          error: "Payment link must use HTTPS."
        });
      }

      const result = await pool.query(
        `UPDATE payment_settings SET
          method_name = COALESCE($1, method_name),
          account_name = COALESCE($2, account_name),
          account_number = COALESCE($3, account_number),
          payment_link = COALESCE($4, payment_link),
          instructions = COALESCE($5, instructions),
          currency = COALESCE($6, currency),
          is_active = COALESCE($7, is_active),
          updated_at = NOW()
         WHERE id = $8
         RETURNING *`,
        [
          method_name ?? null,
          account_name ?? null,
          account_number ?? null,
          payment_link ?? null,
          instructions ?? null,
          currency ?? null,
          typeof is_active === "boolean" ? is_active : null,
          id
        ]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Payment method not found."
        });
      }

      return res.json({
        message: "Payment method updated.",
        paymentMethod: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

/* Submit a deposit request: signed-in users only */
app.post("/api/deposits", requireLogin, async (req, res, next) => {
  try {
    const amount = Number(req.body?.amount);
    const currency = req.body?.currency;
    const note =
      typeof req.body?.note === "string"
        ? req.body.note.trim()
        : "";

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        error: "Enter a valid deposit amount."
      });
    }

    if (!["USD", "ETB"].includes(currency)) {
      return res.status(400).json({
        error: "Currency must be USD or ETB."
      });
    }

    if (note.length > 200) {
      return res.status(400).json({
        error: "Note must be 200 characters or fewer."
      });
    }

    const userId = req.session.user.id;

    const result = await pool.query(
      `INSERT INTO deposit_requests
         (user_id, amount, currency, note, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING id, amount, currency, note, status, created_at`,
      [userId, amount, currency, note || null]
    );

    return res.status(201).json({
      message: "Deposit request submitted for admin review.",
      deposit: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

/* List transfer requests: administrator only */
app.get("/api/admin/transfers", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
         tr.id,
         tr.user_id,
         u.full_name,
         u.email,
         tr.amount,
         tr.currency,
         tr.status,
         tr.created_at,
         tr.reviewed_at
       FROM transfer_requests tr
       JOIN app_users u ON u.id = tr.user_id
       ORDER BY tr.created_at DESC
       LIMIT 500`
    );

    return res.json({
      transfers: result.rows
    });
  } catch (error) {
    next(error);
  }
});

/* Confirm or reject a transfer request: administrator only */
app.patch(
  "/api/admin/transfers/:id/status",
  requireAdmin,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const { status } = req.body || {};

      if (!/^[1-9]\d*$/.test(id)) {
        return res.status(400).json({
          error: "Invalid transfer request ID."
        });
      }

      if (!["confirmed", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Status must be confirmed or rejected."
        });
      }

      const result = await pool.query(
        `UPDATE transfer_requests
         SET status = $1,
             reviewed_at = NOW()
         WHERE id = $2
           AND status = 'pending'
         RETURNING id, amount, currency, status, reviewed_at`,
        [status, id]
      );

      if (result.rowCount === 0) {
        return res.status(409).json({
          error: "Request not found or already reviewed."
        });
      }

      return res.json({
        message: `Request ${status} successfully.`,
        transfer: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

/* List deposit requests: administrator only */
app.get("/api/admin/deposits", requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
         dr.id,
         dr.user_id,
         u.full_name,
         u.email,
         dr.amount,
         dr.currency,
         dr.note,
         dr.status,
         dr.created_at,
         dr.reviewed_at
       FROM deposit_requests dr
       JOIN app_users u ON u.id = dr.user_id
       ORDER BY dr.created_at DESC
       LIMIT 500`
    );

    return res.json({
      deposits: result.rows
    });
  } catch (error) {
    next(error);
  }
});

/* Confirm or reject a deposit request: administrator only */
app.patch(
  "/api/admin/deposits/:id/status",
  requireAdmin,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const { status } = req.body || {};

      if (!/^[1-9]\d*$/.test(id)) {
        return res.status(400).json({
          error: "Invalid deposit request ID."
        });
      }

      if (!["confirmed", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Status must be confirmed or rejected."
        });
      }

      const result = await pool.query(
        `UPDATE deposit_requests
         SET status = $1,
             reviewed_at = NOW()
         WHERE id = $2
           AND status = 'pending'
         RETURNING id, amount, currency, status, reviewed_at`,
        [status, id]
      );

      if (result.rowCount === 0) {
        return res.status(409).json({
          error: "Request not found or already reviewed."
        });
      }

      return res.json({
        message: `Deposit request ${status} successfully.`,
        deposit: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

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
