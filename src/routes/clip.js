// ─────────────────────────────────────────────────────────────
// POST /clip  — Main clip-cutting route.
//
// Pipeline:
//   1. Validate URL (format, domain, MIME, size, redirects)
//   2. Validate timestamps (format, range, max duration)
//   3. Run FFmpeg (sandboxed)
//   4. Stream file back to client
//   5. Clean up output file
// ─────────────────────────────────────────────────────────────

const express = require('express');
const path = require('path');
const { validateUrl } = require('../validators/urlValidator');
const { validateTimeRange } = require('../utils/time');
const { cutClip, deleteClip } = require('../services/ffmpegService');
const config = require('../config');
const logger = require('../utils/logger');

const router = express.Router();

router.post('/', async (req, res) => {
  const startTime = Date.now();
  const { url, start, end } = req.body;

  try {
    // ── Step 1: URL validation ────────────────────────────
    logger.info('Clip request received', { ip: req.ip, url, start, end });

    const urlCheck = await validateUrl(url);
    if (!urlCheck.ok) {
      logger.warn('URL validation failed', { url, reason: urlCheck.reason, ip: req.ip });
      return res.status(400).json({
        status: 'rejected',
        reason: urlCheck.reason,
      });
    }

    // ── Step 2: Timestamp validation ──────────────────────
    const timeCheck = validateTimeRange(start, end, config.MAX_CLIP_DURATION_SECONDS);
    if (!timeCheck.ok) {
      logger.warn('Time validation failed', { start, end, reason: timeCheck.reason, ip: req.ip });
      return res.status(400).json({
        status: 'rejected',
        reason: timeCheck.reason,
      });
    }

    // ── Step 3: FFmpeg clipping ───────────────────────────
    const clipResult = await cutClip(url, start, end);
    if (!clipResult.ok) {
      logger.error('FFmpeg clipping failed', { url, reason: clipResult.reason });
      return res.status(500).json({
        status: 'rejected',
        reason: clipResult.reason,
      });
    }

    // ── Step 4: Send file to client ──────────────────────
    const { filePath, filename } = clipResult;

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'video/mp4');
    res.setHeader('X-Processing-Time-Ms', Date.now() - startTime);

    res.sendFile(filePath, (err) => {
      // ── Step 5: Cleanup ─────────────────────────────────
      deleteClip(filePath);

      if (err && !res.headersSent) {
        logger.error('Error sending clip file', { error: err.message });
        return res.status(500).json({
          status: 'rejected',
          reason: 'Failed to send clip file.',
        });
      }

      logger.info('Clip delivered', {
        filename,
        durationMs: Date.now() - startTime,
        ip: req.ip,
      });
    });
  } catch (err) {
    logger.error('Unhandled error in /clip', { error: err.message, stack: err.stack });
    if (!res.headersSent) {
      return res.status(500).json({
        status: 'rejected',
        reason: 'Internal server error.',
      });
    }
  }
});

module.exports = router;
