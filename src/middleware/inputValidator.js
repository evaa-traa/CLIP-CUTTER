// ─────────────────────────────────────────────────────────────
// Input sanitisation & schema validation middleware.
// ─────────────────────────────────────────────────────────────

const logger = require('../utils/logger');

// Strict HH:MM:SS format — only digits and colons
const TIMESTAMP_REGEX = /^\d{1,2}:\d{2}:\d{2}$/;

// Dangerous keys that could be used for prototype pollution
const POISONED_KEYS = ['__proto__', 'constructor', 'prototype'];

// Control characters that can confuse parsers, bypass validators, or inject into logs
const CONTROL_CHAR_REGEX = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

/**
 * Validate the POST /clip request body.
 * Ensures url, start, end exist and are strings.
 */
function validateClipInput(req, res, next) {
  // ── Prototype pollution guard ──────────────────────────────
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (POISONED_KEYS.includes(key)) {
        logger.warn('Prototype pollution attempt blocked', { ip: req.ip, key });
        return res.status(400).json({
          status: 'rejected',
          reason: 'Invalid request body.',
        });
      }
    }
  }

  const { url, start, end, referer } = req.body;

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

  // ── Referer validation (optional field) ──────────────────
  if (referer !== undefined) {
    if (typeof referer !== 'string') {
      return res.status(400).json({ status: 'rejected', reason: 'Referer must be a string.' });
    }
    if (referer.length > 2048) {
      return res.status(400).json({ status: 'rejected', reason: 'Referer URL too long.' });
    }
    if (referer && !/^https?:\/\//i.test(referer)) {
      return res.status(400).json({ status: 'rejected', reason: 'Referer must be an HTTP/HTTPS URL.' });
    }
    if (CONTROL_CHAR_REGEX.test(referer)) {
      return res.status(400).json({ status: 'rejected', reason: 'Referer contains invalid characters.' });
    }
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

  // ── Block null bytes and control characters ──────────────
  // These can confuse parsers, bypass validators, or inject into logs
  if (CONTROL_CHAR_REGEX.test(url) || CONTROL_CHAR_REGEX.test(start) || CONTROL_CHAR_REGEX.test(end)) {
    logger.warn('Control characters in input blocked', { ip: req.ip });
    return res.status(400).json({
      status: 'rejected',
      reason: 'Input contains invalid characters.',
    });
  }

  // ── Strict timestamp format (prevent injection via start/end) ─
  if (!TIMESTAMP_REGEX.test(start) || !TIMESTAMP_REGEX.test(end)) {
    return res.status(400).json({
      status: 'rejected',
      reason: 'Timestamps must be in HH:MM:SS format.',
    });
  }

  next();
}

module.exports = validateClipInput;

