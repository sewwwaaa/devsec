const { db } = require('../config/db');

const adminController = {
  // Get security audit logs (Admin only)
  getAuditLogs(req, res) {
    db.all('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50', [], (err, logs) => {
      if (err) {
        return res.status(500).json({ success: false, error: 'Failed to retrieve audit logs' });
      }
      return res.json({ success: true, count: logs.length, logs });
    });
  },

  // Get system security and secret status
  getSecurityStatus(req, res) {
    return res.json({
      success: true,
      service: 'TaskShield DevSecOps Platform',
      securityProfile: {
        environment: process.env.NODE_ENV || 'development',
        vaultIntegration: process.env.VAULT_ENABLED === 'true' ? 'Active' : 'Disabled (Using Env Secrets)',
        jwtAlgorithm: 'HS256',
        rateLimiting: 'Active',
        securityHeaders: 'Active (Helmet CSP, HSTS, X-Frame-Options)',
        sastScanPolicy: 'Semgrep + Gitleaks CI/CD Gates Enforced'
      }
    });
  }
};

module.exports = adminController;
