// ─────────────────────────────────────────────────────────────
// Input sanitisation & schema validation middleware.
// ─────────────────────────────────────────────────────────────

const logger = require('../utils/logger');

/**
 * Validate the POST /clip request body.
 * Ensures url, start, end exist and are strings.
 */
function validateClipInput(req, res, next) {
  const { url, start, end } = req.body;

  // ── Existence checks ────────────────────────────────────
  if (!url || !start || !end) {
    logger.warn('Missing required fields', {
      ip: req.ip,
      body: { url: !!url, start: !!start, end: !!end },
    });
    return res.status(400).json({
      status: 'rejected',
      reason: 'Missing required fields: url, start, end.',
    });
  }

  // ── Type checks ─────────────────────────────────────────
  if (typeof url !== 'string' || typeof start !== 'string' || typeof end !== 'string') {
    logger.warn('Invalid field types', { ip: req.ip });
    return res.status(400).json({
      status: 'rejected',
      reason: 'Fields url, start, and end must be strings.',
    });
  }

  // ── Length guards (prevent huge payloads) ────────────────
  if (url.length > 2048) {
    return res.status(400).json({
      status: 'rejected',
      reason: 'URL too long (max 2048 characters).',
    });
  }

  if (start.length > 12 || end.length > 12) {
    return res.status(400).json({
      status: 'rejected',
      reason: 'Timestamp too long.',
    });
  }

  next();
}

module.exports = validateClipInput;
