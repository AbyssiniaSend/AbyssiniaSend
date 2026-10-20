
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const db = require("./database");

const app = express();
const PORT = 3000;

// Read JSON request data
app.use(express.json());

// Serve website files
app.use(express.static(__dirname));

// Demo session configuration for localhost only
app.use(
  session({
    name: "abyssiniasend.sid",
    secret:
      process.env.SESSION_SECRET ||
      "local-demo-secret-change-before-deployment",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 30 * 60 * 1000
    }
  })
);

// Backend health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    project: "AbyssiniaSend",
    message: "Backend is running"
  });
});

// API home
app.get("/api", (req, res) => {
  res.json({
    message: "Welcome to AbyssiniaSend API",
    demo: true
  });
});

// Register a new customer
app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Please provide your name, email and password."
      });
    }

    const cleanName = fullName.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (
      cleanName.length < 2 ||
      cleanName.length > 100 ||
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Check your name, email and password requirements."
      });
    }

    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(cleanEmail);

    if (existingUser) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = db
      .prepare(
        `INSERT INTO users (full_name, email, password_hash)
         VALUES (?, ?, ?)`
      )
      .run(cleanName, cleanEmail, passwordHash);

    req.session.userId = Number(result.lastInsertRowid);

    return res.status(201).json({
      message: "Account created successfully.",
      user: {
        id: Number(result.lastInsertRowid),
        fullName: cleanName,
        email: cleanEmail
      }
    });
  } catch (error) {
    console.error("Registration error:", error.message);

    return res.status(500).json({
      error: "Could not create account. Please try again."
    });
  }
});

// Log in
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        error: "Please enter a valid email and password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const user = db
      .prepare(
        `SELECT id, full_name, email, password_hash
         FROM users
         WHERE email = ?`
      )
      .get(cleanEmail);

    const passwordMatches = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!user || !passwordMatches) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    // Regenerate session after successful authentication
    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: "Could not start a session."
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({
            error: "Could not save your session."
          });
        }

        return res.json({
          message: "Login successful.",
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email
          }
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Login failed. Please try again."
    });
  }
});

// Get the currently logged-in customer
app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  const user = db
    .prepare(
      "SELECT id, full_name, email FROM users WHERE id = ?"
    )
    .get(req.session.userId);

  if (!user) {
    return res.status(401).json({
      error: "Please log in again."
    });
  }

  return res.json({
    user: {
      id: user.id,
      fullName: user.full_name,
      email: user.email
    }
  });
});

// Log out
app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Could not log out."
      });
    }

    res.clearCookie("abyssiniasend.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    });

    return res.json({
      message: "Logged out successfully."
    });
  });
});

app.listen(PORT, () => {
  console.log(`AbyssiniaSend running at http://localhost:${PORT}`);
});
