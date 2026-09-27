const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authLimiter } = require('../middleware/rateLimiter');
const { validateBody, registerSchema, loginSchema } = require('../middleware/validator');

// SECURE Routes
router.post('/login', authLimiter, validateBody(loginSchema), authController.login);
router.post('/register', authLimiter, validateBody(registerSchema), authController.register);

// VULNERABILITY DEMONSTRATION ROUTES (Isolated for Exploit PoC testing)
router.post('/vulnerable-login', authController.vulnerableLogin);
router.get('/vulnerable-jwt-verify', authController.vulnerableJwtValidate);

module.exports = router;
