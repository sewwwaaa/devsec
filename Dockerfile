# Stage 1: Build & Dependencies
FROM node:20-alpine AS builder

WORKDIR /app

# Install security updates
RUN apk update && apk upgrade --no-cache

COPY backend/package*.json ./
RUN npm ci --only=production

# Stage 2: Minimal Secure Runtime
FROM node:20-alpine AS runner

# Security: Install latest patches & dumb-init for proper signal handling
RUN apk update && apk upgrade --no-cache && apk add --no-cache dumb-init

WORKDIR /app

# Ensure non-root execution (Least Privilege principle)
USER node

# Copy dependencies and application code with correct ownership
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node backend/ ./
COPY --chown=node:node frontend/ ../frontend/

ENV NODE_ENV=production
ENV PORT=5000

# Container Healthcheck (Mitigates undetected failure / DoS)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

EXPOSE 5000

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "src/server.js"]
