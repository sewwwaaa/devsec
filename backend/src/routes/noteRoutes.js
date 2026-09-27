const express = require('express');
const router = express.Router();
const noteController = require('../controllers/noteController');
const { authenticateToken } = require('../middleware/auth');
const { validateBody, noteSchema } = require('../middleware/validator');

// SECURE Routes (Protected with JWT & RBAC & Input Validation)
router.post('/', authenticateToken, validateBody(noteSchema), noteController.createNote);
router.get('/', authenticateToken, noteController.getMyNotes);
router.get('/:id', authenticateToken, noteController.getNoteById);
router.delete('/:id', authenticateToken, noteController.deleteNote);

// VULNERABILITY DEMONSTRATION ROUTES (Isolated for Exploit PoC testing)
// Exploit 2: Stored XSS Demo Endpoint (allows injecting raw HTML)
router.post('/demo/xss', noteController.vulnerableCreateNote);

// Exploit 3: BOLA / IDOR Demo Endpoints (omits user authorization verification)
router.get('/demo/bola/:id', noteController.vulnerableGetNoteById);
router.delete('/demo/bola/:id', noteController.vulnerableDeleteNote);

module.exports = router;
