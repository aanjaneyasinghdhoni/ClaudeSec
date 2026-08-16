# ── Stage 1: Target-arch dependencies ────────────────────────────────────────
# Runs once per target platform so native modules (better-sqlite3, re2) are
# compiled for the architecture the image will actually run on.
FROM node:22-alpine AS deps
WORKDIR /app

# Enable corepack so pnpm is available without a global install
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# ── Stage 2: Test gate + frontend build ──────────────────────────────────────
# Pinned to the build platform so it runs on native hardware exactly once.
# The test gate includes wall-clock ReDoS timing assertions that fail under
# QEMU emulation (every pattern looks "slow" on an emulated CPU); the vite
# output is plain JS/CSS and identical for every architecture anyway.
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder
WORKDIR /app

RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# ── Stage 3: Production image ────────────────────────────────────────────────
FROM node:22-alpine
WORKDIR /app

# procps for ps aux (process scanner), su-exec to drop root privileges
RUN apk add --no-cache procps su-exec && corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Reuse the native binaries already compiled in the deps stage — avoids
# re-running node-gyp for better-sqlite3 / re2 in a minimal prod image.
# pnpm's node_modules layout (including the .pnpm store) uses relative symlinks
# and is fully self-contained, so copying the whole directory is safe.
COPY --from=deps /app/node_modules ./node_modules

# Copy backend TypeScript modules + tsconfig so tsx can resolve all imports.
COPY server/ ./server/
COPY tsconfig.json ./
COPY src/harnesses.ts ./src/
# server/index.ts imports from src/shared (e.g. types.ts); copy it so tsx
# can resolve those imports at runtime in the production container.
COPY src/shared/ ./src/shared/

# Copy frontend build
COPY --from=builder /app/dist ./dist

# Everything that must outlive the image lives in /data, and nowhere else.
#
# This used to be arranged with `ln -sf /data/spans.db /app/spans.db`, which
# worked only while the database path was a bare filename resolved against the
# working directory. It is now an absolute path under the process's HOME — and
# HOME in this container is /home/node, inside the WRITABLE LAYER. A layer is
# discarded on every `docker compose pull` / rebuild, so the database, the audit
# log and the Ed25519 key that signs the hash-chain anchor were all being thrown
# away on upgrade while the volume held nothing but exports.
#
# Set as ENV in the image rather than in docker-compose.yml so a plain
# `docker run -v claudesec-data:/data claudesec` is correct too — the persistence
# contract belongs to the image, not to one way of starting it.
#
#   CLAUDESEC_DB           the SQLite ledger. /data/spans.db is exactly where
#                          the 1.3.0 symlink put it, so an existing volume is
#                          picked up as-is, with its history intact.
#   CLAUDESEC_HOME         hooks/ — the audit signing key, the signed tail
#                          anchor, the pairing key. Losing the key alone would
#                          make every chain written before an upgrade
#                          unverifiable, even with the database preserved.
#   CLAUDESEC_RULES_FILE   custom rules, previously the /app/rules.json symlink.
#   CLAUDESEC_AUTO_EXPORT_DIR  hourly JSON snapshots.
ENV CLAUDESEC_DB=/data/spans.db
ENV CLAUDESEC_HOME=/data/claudesec
ENV CLAUDESEC_RULES_FILE=/data/rules.json
ENV CLAUDESEC_AUTO_EXPORT_DIR=/data/exports

RUN mkdir -p /data && chown -R node:node /app /data

# Declared so `docker run` without an explicit -v still gets a real volume
# instead of silently writing the ledger into a disposable layer. Compose
# overrides it with the named claudesec-data volume.
VOLUME ["/data"]

EXPOSE 3000
ENV NODE_ENV=production
ENV PORT=3000
ENV CLAUDESEC_HOST=0.0.0.0

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

# The chown runs as root on every start because a freshly-created named volume
# (and any host directory bind-mounted in its place) belongs to root until
# something fixes it — the server then runs as `node` and creates
# /data/claudesec/hooks 0700 and /data/spans.db 0600 itself.
CMD ["sh", "-c", "mkdir -p /data/claudesec /data/exports 2>/dev/null; chown -R node:node /data 2>/dev/null || true; exec su-exec node node --import tsx server/index.ts"]
