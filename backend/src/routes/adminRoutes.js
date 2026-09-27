const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authenticateToken, requireRole } = require('../middleware/auth');

// Protected admin routes: requires valid token AND admin role
router.get('/audit-logs', authenticateToken, requireRole(['admin']), adminController.getAuditLogs);
router.get('/security-status', authenticateToken, requireRole(['admin']), adminController.getSecurityStatus);

module.exports = router;
