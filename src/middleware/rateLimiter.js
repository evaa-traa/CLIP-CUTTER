// ─────────────────────────────────────────────────────────────
// Express middleware: rate limiter setup.
// ─────────────────────────────────────────────────────────────

const rateLimit = require('express-rate-limit');
const config = require('../config');
const logger = require('../utils/logger');

const clipRateLimiter = rateLimit({
  windowMs: config.RATE_LIMIT_WINDOW_MS,
  max: config.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  // Use the default key generator (req.ip) — handles IPv6 correctly
  // trust proxy is already set in app.js so X-Forwarded-For works
  message: {
    status: 'rejected',
    reason: `Rate limit exceeded. Maximum ${config.RATE_LIMIT_MAX_REQUESTS} requests per minute.`,
  },
  handler: (req, res, _next, options) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      path: req.path,
    });
    res.status(429).json(options.message);
  },
});

module.exports = clipRateLimiter;

