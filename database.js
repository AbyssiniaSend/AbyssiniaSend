
const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "abyssiniasend.db"));

// Enable foreign-key checks
db.pragma("foreign_keys = ON");

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// Create payment requests table
db.exec(`
  CREATE TABLE IF NOT EXISTS payment_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    recipient_full_name TEXT NOT NULL,
    bank_name TEXT NOT NULL,
    account_number TEXT NOT NULL,
    amount REAL NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL DEFAULT 'USD',
    transaction_reference TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'PENDING'
      CHECK (status IN (
        'PENDING',
        'UNDER_REVIEW',
        'PAYMENT_CONFIRMED',
        'REJECTED',
        'TRANSFER_COMPLETED'
      )),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

console.log("AbyssiniaSend database is ready.");

module.exports = db;
