# ─────────────────────────────────────────────────────────────
# Clip Cutter — Production Dockerfile
#
# Multi-stage build:
#   Stage 1: Install Node dependencies (cached layer)
#   Stage 2: Slim runtime with FFmpeg installed
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Dependencies ────────────────────────────────────
FROM node:20-slim AS deps

WORKDIR /app

# Copy only package files first for better layer caching
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --omit=dev

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM node:20-slim AS runtime

# Install FFmpeg
RUN apt-get update && \
    apt-get install -y --no-install-recommends ffmpeg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r clipcutter && useradd -r -g clipcutter -m clipcutter

WORKDIR /app

# Copy dependencies from build stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY src ./src
COPY public ./public

# Create output directories and set ownership
RUN mkdir -p clips logs && chown -R clipcutter:clipcutter /app

# Switch to non-root user
USER clipcutter

# Expose port (Render uses PORT env var, default 3000)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const http = require('http'); http.get('http://localhost:' + (process.env.PORT || 3000) + '/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Start the application
CMD ["node", "src/app.js"]
