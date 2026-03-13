// ─────────────────────────────────────────────────────────────
// Winston logger — structured JSON logs + console output.
// ─────────────────────────────────────────────────────────────

const { createLogger, format, transports } = require('winston');
const path = require('path');
const fs = require('fs');
const config = require('../config');

// Ensure log directory exists
if (!fs.existsSync(config.LOG_DIR)) {
  fs.mkdirSync(config.LOG_DIR, { recursive: true });
}

const logger = createLogger({
  level: config.LOG_LEVEL,
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'clip-cutter' },
  transports: [
    // ── Console (colourised for dev) ────────────────────────
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(({ timestamp, level, message, ...meta }) => {
          const metaStr = Object.keys(meta).length > 1
            ? ` ${JSON.stringify(meta)}`
            : '';
          return `${timestamp} [${level}]: ${message}${metaStr}`;
        })
      ),
    }),

    // ── File: combined ──────────────────────────────────────
    new transports.File({
      filename: path.join(config.LOG_DIR, 'combined.log'),
      maxsize: 5 * 1024 * 1024, // 5 MB rotation
      maxFiles: 5,
    }),

    // ── File: errors only ───────────────────────────────────
    new transports.File({
      filename: path.join(config.LOG_DIR, 'error.log'),
      level: 'error',
      maxsize: 5 * 1024 * 1024,
      maxFiles: 5,
    }),

    // ── File: rejected requests ─────────────────────────────
    new transports.File({
      filename: path.join(config.LOG_DIR, 'rejected.log'),
      level: 'warn',
      maxsize: 5 * 1024 * 1024,
      maxFiles: 5,
    }),
  ],
});

module.exports = logger;
