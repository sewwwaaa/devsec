const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

// Database storage directory
const dataDir = path.resolve(__dirname, '../../data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = process.env.DB_PATH || path.join(dataDir, 'taskshield.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[DB] Connection error:', err.message);
  } else {
    console.log(`[DB] Connected to SQLite database at ${dbPath}`);
  }
});

// Initialize database schema and initial seed data
function initDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Notes and Tasks table
      db.run(`
        CREATE TABLE IF NOT EXISTS notes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          content TEXT NOT NULL,
          category TEXT DEFAULT 'general',
          is_confidential INTEGER DEFAULT 0,
          userId INTEGER NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
        )
      `);

      // Security Audit Logs table (Repudiation mitigation)
      db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          userId INTEGER,
          action TEXT NOT NULL,
          details TEXT,
          status TEXT NOT NULL,
          ip_address TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Check if users exist; if not, seed initial users
      db.get('SELECT COUNT(*) as count FROM users', async (err, row) => {
        if (err) return reject(err);

        if (row.count === 0) {
          console.log('[DB] Seeding default users (Admin & Standard)...');
          const adminPass = await bcrypt.hash('AdminSecurePass!2026', 10);
          const userAlicePass = await bcrypt.hash('AlicePass!2026', 10);
          const userBobPass = await bcrypt.hash('BobPass!2026', 10);

          db.run(
            `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
            ['admin', 'admin@taskshield.local', adminPass, 'admin']
          );
          db.run(
            `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
            ['alice', 'alice@taskshield.local', userAlicePass, 'user']
          );
          db.run(
            `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`,
            ['bob', 'bob@taskshield.local', userBobPass, 'user'],
            function () {
              // Seed confidential notes for Alice (used for BOLA IDOR exploit proof)
              db.run(
                `INSERT INTO notes (title, content, category, is_confidential, userId) VALUES (?, ?, ?, ?, ?)`,
                [
                  'Alice Private Financial Plan',
                  'Confidential company audit budget: $450,000. Do not disclose.',
                  'finance',
                  1,
                  2 // Alice ID
                ]
              );
              db.run(
                `INSERT INTO notes (title, content, category, is_confidential, userId) VALUES (?, ?, ?, ?, ?)`,
                [
                  'Bob Public Checklist',
                  'Review Docker Compose configuration and verify container ports.',
                  'devops',
                  0,
                  3 // Bob ID
                ]
              );
              console.log('[DB] Default seed data initialized.');
              resolve(db);
            }
          );
        } else {
          resolve(db);
        }
      });
    });
  });
}

module.exports = {
  db,
  initDatabase
};
