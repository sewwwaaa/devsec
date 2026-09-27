const sanitizeHtml = require('sanitize-html');
const { db } = require('../config/db');

/**
 * Controller for Task and Note Operations
 * Demonstrates Stored XSS mitigation (CWE-79) and BOLA/IDOR mitigation (CWE-639)
 */
const noteController = {
  // SECURE: Create Note with Strict Input Sanitization
  createNote(req, res) {
    const { title, content, category, is_confidential } = req.body;
    const userId = req.user.id;

    if (!title || !content) {
      return res.status(400).json({ success: false, error: 'Title and content required' });
    }

    // SECURE FIX for XSS (CWE-79): Sanitize HTML removing dangerous scripts, events, protocols
    const sanitizedTitle = sanitizeHtml(title, {
      allowedTags: [],
      allowedAttributes: {}
    });

    const sanitizedContent = sanitizeHtml(content, {
      allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'li', 'code'],
      allowedAttributes: {
        'a': ['href', 'target']
      }
    });

    db.run(
      `INSERT INTO notes (title, content, category, is_confidential, userId) VALUES (?, ?, ?, ?, ?)`,
      [sanitizedTitle, sanitizedContent, category || 'general', is_confidential ? 1 : 0, userId],
      function (err) {
        if (err) {
          return res.status(500).json({ success: false, error: 'Failed to create note' });
        }

        return res.status(201).json({
          success: true,
          message: 'Note created securely',
          note: {
            id: this.lastID,
            title: sanitizedTitle,
            content: sanitizedContent,
            category,
            userId
          }
        });
      }
    );
  },

  // SECURE: Get All Notes Belonging to the Authenticated User (Multi-tenant isolation)
  getMyNotes(req, res) {
    const userId = req.user.id;

    db.all(
      `SELECT id, title, content, category, is_confidential, created_at FROM notes WHERE userId = ? ORDER BY id DESC`,
      [userId],
      (err, notes) => {
        if (err) {
          return res.status(500).json({ success: false, error: 'Failed to retrieve notes' });
        }
        return res.json({ success: true, count: notes.length, notes });
      }
    );
  },

  // SECURE: Get Note by ID with Strict Ownership Authorization (Mitigates BOLA/IDOR CWE-639)
  getNoteById(req, res) {
    const noteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Check ownership or admin privilege
    db.get('SELECT * FROM notes WHERE id = ?', [noteId], (err, note) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      if (!note) {
        return res.status(404).json({ success: false, error: 'Note not found' });
      }

      // Strict Access Control Check
      if (note.userId !== userId && userRole !== 'admin') {
        // Audit log unauthorized access attempt
        db.run('INSERT INTO audit_logs (userId, action, details, status, ip_address) VALUES (?, ?, ?, ?, ?)',
          [userId, 'UNAUTHORIZED_ACCESS_ATTEMPT', `Attempted to access note ID ${noteId} owned by user ${note.userId}`, 'BLOCKED', req.ip]);

        return res.status(403).json({
          success: false,
          error: 'Forbidden: You do not have permission to view this resource.'
        });
      }

      return res.json({ success: true, note });
    });
  },

  // SECURE: Delete Note with Ownership Verification
  deleteNote(req, res) {
    const noteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    db.get('SELECT * FROM notes WHERE id = ?', [noteId], (err, note) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      if (!note) {
        return res.status(404).json({ success: false, error: 'Note not found' });
      }

      if (note.userId !== userId && userRole !== 'admin') {
        return res.status(403).json({
          success: false,
          error: 'Forbidden: Cannot delete resources owned by another user.'
        });
      }

      db.run('DELETE FROM notes WHERE id = ?', [noteId], function (delErr) {
        if (delErr) {
          return res.status(500).json({ success: false, error: 'Delete operation failed' });
        }
        return res.json({ success: true, message: `Note ${noteId} deleted successfully.` });
      });
    });
  },

  // VULNERABLE ENDPOINT: Create Note WITHOUT Sanitization (Demonstrates Stored XSS: CWE-79)
  vulnerableCreateNote(req, res) {
    const { title, content, category } = req.body;
    const userId = req.user ? req.user.id : 1;

    // INSECURE: Directly storing raw unescaped input
    db.run(
      `INSERT INTO notes (title, content, category, is_confidential, userId) VALUES (?, ?, ?, 0, ?)`,
      [title, content, category || 'general', userId],
      function (err) {
        if (err) {
          return res.status(500).json({ success: false, error: err.message });
        }

        return res.status(201).json({
          success: true,
          vulnerableNotice: 'STORED XSS DEMO: Raw unsanitized payload stored in database',
          noteId: this.lastID,
          rawPayload: { title, content }
        });
      }
    );
  },

  // VULNERABLE ENDPOINT: Get Note by ID WITHOUT Ownership Check (Demonstrates BOLA/IDOR: CWE-639)
  vulnerableGetNoteById(req, res) {
    const noteId = req.params.id;

    // INSECURE: Directly fetching by ID without validating whether req.user.id matches note.userId
    db.get('SELECT * FROM notes WHERE id = ?', [noteId], (err, note) => {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }
      if (!note) {
        return res.status(404).json({ success: false, error: 'Note not found' });
      }

      return res.json({
        success: true,
        vulnerableNotice: 'BOLA/IDOR DEMO: Object retrieved without tenant boundary validation',
        note
      });
    });
  },

  // VULNERABLE ENDPOINT: Delete Note WITHOUT Ownership Check (Demonstrates BOLA/IDOR: CWE-639)
  vulnerableDeleteNote(req, res) {
    const noteId = req.params.id;

    // INSECURE: Deleting any resource without checking owner
    db.run('DELETE FROM notes WHERE id = ?', [noteId], function (err) {
      if (err) {
        return res.status(500).json({ success: false, error: err.message });
      }

      return res.json({
        success: true,
        vulnerableNotice: 'BOLA/IDOR DEMO: Resource deleted without ownership verification',
        deletedNoteId: noteId,
        rowsAffected: this.changes
      });
    });
  }
};

module.exports = noteController;
