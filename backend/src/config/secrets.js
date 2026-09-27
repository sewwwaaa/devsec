/**
 * DevSecOps Secrets Manager Module
 * Handles runtime secret resolution via:
 * 1. Environment variables (e.g. GitHub Actions encrypted secrets / Docker secrets)
 * 2. HashiCorp Vault HTTP API dynamic runtime injection
 * 
 * Satisfies Assignment Section 2.5 (Secrets Management)
 */
const http = require('http');

let runtimeSecrets = {
  jwtSecret: process.env.JWT_SECRET || null,
  dbPath: process.env.DB_PATH || './data/taskshield.sqlite',
  env: process.env.NODE_ENV || 'development'
};

/**
 * Attempt to pull dynamic secrets from HashiCorp Vault if enabled
 */
async function fetchVaultSecret(vaultAddr, vaultToken, secretPath) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(`${vaultAddr}/v1/${secretPath}`);
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'GET',
        headers: {
          'X-Vault-Token': vaultToken,
          'Content-Type': 'application/json'
        },
        timeout: 3000
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(data);
              resolve(parsed.data?.data || parsed.data);
            } catch (err) {
              reject(new Error('Failed to parse Vault response JSON'));
            }
          } else {
            reject(new Error(`Vault returned status ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Vault request timed out'));
      });
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Initialize secrets at startup
 */
async function loadSecrets() {
  if (process.env.VAULT_ENABLED === 'true' && process.env.VAULT_TOKEN) {
    console.log('[SECRETS] HashiCorp Vault integration is ENABLED. Fetching runtime secrets...');
    try {
      const vaultData = await fetchVaultSecret(
        process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
        process.env.VAULT_TOKEN,
        process.env.VAULT_SECRET_PATH || 'secret/data/taskshield'
      );
      if (vaultData && vaultData.JWT_SECRET) {
        runtimeSecrets.jwtSecret = vaultData.JWT_SECRET;
        console.log('[SECRETS] Successfully injected JWT_SECRET from HashiCorp Vault at runtime.');
      }
    } catch (err) {
      console.warn(`[SECRETS] Vault fetch failed: ${err.message}. Falling back to environment variables.`);
    }
  }

  // Ensure a secret is present
  if (!runtimeSecrets.jwtSecret) {
    if (process.env.NODE_ENV === 'production') {
      console.error('[CRITICAL SECURITY ERROR] JWT_SECRET is not configured! Aborting startup in production.');
      process.exit(1);
    } else {
      console.warn('[SECURITY WARNING] No JWT_SECRET set. Using development fallback. DO NOT USE IN PRODUCTION.');
      runtimeSecrets.jwtSecret = 'dev_only_insecure_fallback_key_32_chars_long!';
    }
  }

  return runtimeSecrets;
}

function getJwtSecret() {
  return runtimeSecrets.jwtSecret;
}

module.exports = {
  loadSecrets,
  getJwtSecret,
  runtimeSecrets
};
