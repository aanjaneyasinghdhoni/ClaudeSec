# ── Stage 1: Build frontend ──────────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

# Enable corepack so pnpm is available without a global install
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# ── Stage 2: Production image ────────────────────────────────────────────────
FROM node:22-alpine
WORKDIR /app

# procps for ps aux (process scanner), su-exec to drop root privileges
RUN apk add --no-cache procps su-exec && corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Reuse the native binaries already compiled in the builder stage — avoids
# re-running node-gyp for better-sqlite3 / re2 in a minimal prod image.
# pnpm's node_modules layout (including the .pnpm store) uses relative symlinks
# and is fully self-contained, so copying the whole directory is safe.
COPY --from=builder /app/node_modules ./node_modules

# Copy backend TypeScript modules + tsconfig so tsx can resolve all imports.
COPY server/ ./server/
COPY tsconfig.json ./
COPY src/harnesses.ts ./src/
# server/index.ts imports from src/shared (e.g. types.ts); copy it so tsx
# can resolve those imports at runtime in the production container.
COPY src/shared/ ./src/shared/

# Copy frontend build
COPY --from=builder /app/dist ./dist

# SQLite DB and custom rules are mounted via volume — create data dir and
# point the app paths to /data so both survive container restarts.
RUN mkdir -p /data \
  && ln -sf /data/spans.db /app/spans.db \
  && ln -sf /data/rules.json /app/rules.json \
  && chown -R node:node /app

EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000
ENV CLAUDESEC_HOST=0.0.0.0

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

CMD ["sh", "-c", "chown -R node:node /data 2>/dev/null || true; exec su-exec node node --import tsx server/index.ts"]
