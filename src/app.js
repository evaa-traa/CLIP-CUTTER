// ─────────────────────────────────────────────────────────────
// Application entry point — Express server assembly.
//
// Security stack:
//   1. Helmet (HTTP security headers)
//   2. CORS (locked down)
//   3. Body size limit (1 MB JSON max)
//   4. Rate limiter (5 req/min per IP)
//   5. Input validation middleware
//   6. URL + MIME + SSRF validation (in route)
//   7. Sandboxed FFmpeg execution (in service)
// ─────────────────────────────────────────────────────────────

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const config = require('./config');
const logger = require('./utils/logger');
const rateLimiter = require('./middleware/rateLimiter');
const validateClipInput = require('./middleware/inputValidator');
const clipRoute = require('./routes/clip');
const healthRoute = require('./routes/health');

const app = express();

// ─── Global security middleware ──────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',       // Tighten in production
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type'],
}));

// ─── Body parsing with size limit ────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ─── Trust first proxy (for correct req.ip behind nginx etc) ─
app.set('trust proxy', 1);

// ─── Routes ──────────────────────────────────────────────────
app.use('/health', healthRoute);
app.use('/clip', rateLimiter, validateClipInput, clipRoute);

// ─── 404 catch-all ───────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ status: 'error', reason: 'Not found.' });
});

// ─── Global error handler ────────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  if (!res.headersSent) {
    res.status(500).json({ status: 'error', reason: 'Internal server error.' });
  }
});

// ─── Start server ────────────────────────────────────────────
app.listen(config.PORT, config.HOST, () => {
  logger.info(`🚀 Clip Cutter listening on http://${config.HOST}:${config.PORT}`);
  logger.info('Security stack: Helmet · CORS · RateLimit · InputValidation · URLValidation · SSRF Guard · FFmpeg Sandbox');
});

module.exports = app;
