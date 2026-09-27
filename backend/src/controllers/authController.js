const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../config/db');
const { getJwtSecret } = require('../config/secrets');

/**
 * SECURE Authentication Controller
 * Parameterized queries, bcrypt password hashing, cryptographically signed JWT
 */
const authController = {
  // SECURE LOGIN: Parameterized query & bcrypt verification
  async login(req, res) {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }

    // Secure: Parameterized SQL prevents SQL Injection (CWE-89)
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      if (!user) {
        return res.status(401).json({ success: false, error: 'Invalid username or password' });
      }

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        // Audit log failed attempt
        db.run('INSERT INTO audit_logs (userId, action, status, ip_address) VALUES (?, ?, ?, ?)',
          [user.id, 'LOGIN_FAILED', 'FAILURE', req.ip]);
        return res.status(401).json({ success: false, error: 'Invalid username or password' });
      }

      // Secure JWT token generation with expiration
      const secret = getJwtSecret();
      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email, role: user.role },
        secret,
        { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
      );

      // Audit log success
      db.run('INSERT INTO audit_logs (userId, action, status, ip_address) VALUES (?, ?, ?, ?)',
        [user.id, 'LOGIN_SUCCESS', 'SUCCESS', req.ip]);

      return res.json({
        success: true,
        message: 'Authentication successful',
        token,
        user: { id: user.id, username: user.username, email: user.email, role: user.role }
      });
    });
  },

  // SECURE REGISTRATION
  async register(req, res) {
    const { username, email, password } = req.validatedBody || req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
        [username, email, hashedPassword, 'user'],
        function (err) {
          if (err) {
            if (err.message.includes('UNIQUE')) {
              return res.status(409).json({ success: false, error: 'Username or email already exists' });
            }
            return res.status(500).json({ success: false, error: 'Registration failed' });
          }

          return res.status(201).json({
            success: true,
            message: 'User registered successfully',
            userId: this.lastID
          });
        }
      );
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Password hashing error' });
    }
  },

  // VULNERABLE LOGIN (For Exploit Demonstration & SAST verification: CWE-89)
  // Flaw: Direct string concatenation allows SQL Injection authentication bypass
  vulnerableLogin(req, res) {
    const { username, password } = req.body;

    // INSECURE: Vulnerable SQL query vulnerable to ' OR '1'='1' or comment-based bypass
    const rawQuery = `SELECT * FROM users WHERE username = '${username}'`;

    db.get(rawQuery, (err, user) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'SQL Syntax/Execution error: ' + err.message });
      }

      if (!user) {
        return res.status(401).json({ success: false, error: 'User not found' });
      }

      // If user object returned by injection, issues token even without password verification!
      const secret = getJwtSecret();
      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email, role: user.role },
        secret,
        { expiresIn: '1h' }
      );

      return res.json({
        success: true,
        vulnerableNotice: 'VULNERABILITY DEMO: Logged in via SQL injection bypass',
        token,
        user: { id: user.id, username: user.username, email: user.email, role: user.role }
      });
    });
  },

  // VULNERABLE JWT VALIDATION (For Exploit Demonstration: CWE-798 Hardcoded Secret)
  vulnerableJwtValidate(req, res) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    // INSECURE: Verification using weak hardcoded fallback secret "secret123"
    const WEAK_HARDCODED_SECRET = 'secret123';
    try {
      const decoded = jwt.verify(token, WEAK_HARDCODED_SECRET);
      return res.json({
        success: true,
        message: 'Token accepted via weak hardcoded secret!',
        decoded
      });
    } catch (err) {
      return res.status(403).json({ success: false, error: 'Weak token verification failed: ' + err.message });
    }
  }
};

module.exports = authController;
