require('dotenv').config();
const app = require('./app');
const { initDatabase } = require('./config/db');
const { loadSecrets } = require('./config/secrets');

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    // 1. Resolve runtime secrets (Env vars or HashiCorp Vault)
    await loadSecrets();

    // 2. Initialize database schema & seed data
    await initDatabase();

    // 3. Start HTTP server
    const server = app.listen(PORT, () => {
      console.log('====================================================');
      console.log(`🛡️  TaskShield DevSecOps Platform running on port ${PORT}`);
      console.log(`🔗 API Base: http://localhost:${PORT}/api`);
      console.log(`🌐 Web UI:   http://localhost:${PORT}`);
      console.log(`🩺 Health:   http://localhost:${PORT}/api/health`);
      console.log('====================================================');
    });

    // Graceful shutdown handling
    const shutdown = () => {
      console.log('\n[SERVER] Gracefully shutting down...');
      server.close(() => {
        console.log('[SERVER] Closed remaining connections.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    console.error('[FATAL] Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
