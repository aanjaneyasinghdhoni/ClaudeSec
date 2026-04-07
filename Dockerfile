# ── Stage 1: Build frontend ──────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Stage 2: Production image ────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Install production deps + tsx (runtime TypeScript runner)
COPY package*.json ./
RUN npm ci && npm install -g tsx

# Copy source (server needs harnesses.ts at runtime)
COPY server.ts tsconfig.json ./
COPY src/harnesses.ts ./src/

# Copy frontend build
COPY --from=builder /app/dist ./dist

# SQLite DB is mounted via volume — create data dir
RUN mkdir -p /data && ln -s /data/spans.db /app/spans.db 2>/dev/null || true

EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1

CMD ["tsx", "server.ts"]
