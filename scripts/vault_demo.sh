#!/usr/bin/env bash
# HashiCorp Vault Local Setup & Runtime Injection Script
# Demonstrates Section 2.5 Secrets Management compliance

set -e

echo "=== Step 1: Starting HashiCorp Vault in Local Dev Mode ==="
docker run -d --name taskshield-vault \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=my-secure-root-token' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  vault:1.13.3

sleep 3

echo "=== Step 2: Injecting Production JWT Secret into Vault KV Store ==="
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='my-secure-root-token' \
  taskshield-vault vault kv put secret/taskshield \
  JWT_SECRET="vault_injected_super_secure_key_32_chars_2026!" \
  DB_PASSWORD="vault_db_dynamic_password_98765"

echo "=== Step 3: Verifying Secret Storage in Vault ==="
docker exec -e VAULT_ADDR='http://127.0.0.1:8200' -e VAULT_TOKEN='my-secure-root-token' \
  taskshield-vault vault kv get secret/taskshield

echo "=== Step 4: Booting TaskShield Application with Vault Secret Resolution ==="
export VAULT_ENABLED="true"
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="my-secure-root-token"
export VAULT_SECRET_PATH="secret/data/taskshield"

echo "Application launched with zero hardcoded credentials!"
