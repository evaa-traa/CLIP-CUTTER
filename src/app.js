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
const path = require('path');
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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", "data:"],
    },
  },
}));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',       // Tighten in production
  methods: ['POST', 'GET'],
  allowedHeaders: ['Content-Type'],
}));

// ─── Body parsing with size limit ────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ─── Trust first proxy (for correct req.ip behind nginx etc) ─
app.set('trust proxy', 1);

// ─── Serve static frontend ───────────────────────────────────
app.use(express.static(path.resolve(__dirname, '..', 'public')));

// ─── API Routes ──────────────────────────────────────────────
app.get('/api/info', (_req, res) => {
  res.json({
    service: 'clip-cutter',
    version: '1.0.0',
    endpoints: {
      'GET  /':        'Web UI',
      'GET  /health':  'Health check (includes FFmpeg status)',
      'POST /clip':    'Cut a clip — body: { url, start, end }',
      'GET  /api/info': 'This info page (JSON)',
    },
  });
});
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
