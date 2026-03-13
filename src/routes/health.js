// ─────────────────────────────────────────────────────────────
// Health check route.
// ─────────────────────────────────────────────────────────────

const express = require('express');
const { execSync } = require('child_process');
const config = require('../config');
const router = express.Router();

router.get('/', (_req, res) => {
  let ffmpegOk = false;
  try {
    execSync(`${config.FFMPEG_PATH} -version`, { timeout: 5000, stdio: 'pipe' });
    ffmpegOk = true;
  } catch { /* ffmpeg not found */ }

  res.json({
    status: 'ok',
    service: 'clip-cutter',
    ffmpeg: ffmpegOk ? 'available' : 'NOT FOUND — clips will fail',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
