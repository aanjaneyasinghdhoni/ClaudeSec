# ── Stage 1: Build frontend ──────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Stage 2: Production image ────────────────────────────────────────────────
FROM node:22-alpine
WORKDIR /app

# procps for ps aux (process scanner), su-exec to drop root privileges
RUN apk add --no-cache procps su-exec
COPY package*.json ./
RUN npm ci --omit=dev

# Copy source (server needs harnesses + scrub modules at runtime)
COPY server.ts scrub.ts tsconfig.json ./
COPY src/harnesses.ts ./src/

# Copy frontend build
COPY --from=builder /app/dist ./dist

# SQLite DB is mounted via volume — create data dir
RUN mkdir -p /data \
  && ln -sf /data/spans.db /app/spans.db \
  && chown -R node:node /app

EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000
ENV CLAUDESEC_HOST=0.0.0.0

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1

CMD ["sh", "-c", "chown -R node:node /data 2>/dev/null || true; exec su-exec node node --import tsx server.ts"]
