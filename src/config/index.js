// ─────────────────────────────────────────────────────────────
// Centralised configuration — all tunables live here.
// ─────────────────────────────────────────────────────────────

const path = require('path');

const config = {
  // ── Server ────────────────────────────────────────────────
  PORT: parseInt(process.env.PORT, 10) || 3000,
  HOST: process.env.HOST || '0.0.0.0',

  // ── Clip constraints ─────────────────────────────────────
  MAX_CLIP_DURATION_SECONDS: 90,
  MAX_FILE_SIZE_BYTES: 500 * 1024 * 1024,           // 500 MB

  // ── FFmpeg ────────────────────────────────────────────────
  FFMPEG_TIMEOUT_MS: 120_000,                         // 2 min execution cap
  FFMPEG_PATH: process.env.FFMPEG_PATH || 'ffmpeg',   // override if needed

  // ── Network ───────────────────────────────────────────────
  MAX_REDIRECTS: 2,
  HEAD_REQUEST_TIMEOUT_MS: 10_000,

  // ── Rate limiting ─────────────────────────────────────────
  RATE_LIMIT_WINDOW_MS: 60_000,                       // 1 min
  RATE_LIMIT_MAX_REQUESTS: 5,

  // ── Allowed MIME types ────────────────────────────────────
  ALLOWED_CONTENT_TYPES: [
    'application/vnd.apple.mpegurl',
    'application/x-mpegurl',
    'video/mp4',
    'video/webm',
    'video/mp2t',
  ],

  // ── Blocked MIME types ────────────────────────────────────
  BLOCKED_CONTENT_TYPES: [
    'text/html',
    'application/javascript',
    'application/json',
    'text/javascript',
  ],

  // ── Allowed file extensions ───────────────────────────────
  ALLOWED_EXTENSIONS: ['.m3u8', '.mp4', '.webm', '.ts'],

  // ── Output directory ──────────────────────────────────────
  OUTPUT_DIR: path.resolve(__dirname, '..', '..', 'clips'),

  // ── Logging ───────────────────────────────────────────────
  LOG_DIR: path.resolve(__dirname, '..', '..', 'logs'),
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
};

module.exports = config;
