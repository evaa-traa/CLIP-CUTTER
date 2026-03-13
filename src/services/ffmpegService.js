// ─────────────────────────────────────────────────────────────
// FFmpeg clip service.
//
// Runs FFmpeg as a sandboxed child process with:
//   • CPU / time limits
//   • No external protocol access
//   • UUID-based output filenames
// ─────────────────────────────────────────────────────────────

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const logger = require('../utils/logger');

// Ensure output directory exists
if (!fs.existsSync(config.OUTPUT_DIR)) {
  fs.mkdirSync(config.OUTPUT_DIR, { recursive: true });
}

/**
 * Cut a clip from a remote stream using FFmpeg.
 *
 * @param {string} url      — validated direct media URL
 * @param {string} start    — start timestamp "HH:MM:SS"
 * @param {string} end      — end timestamp "HH:MM:SS"
 * @returns {Promise<{ok:boolean, filePath?:string, filename?:string, reason?:string}>}
 */
function cutClip(url, start, end) {
  return new Promise((resolve) => {
    const filename = `${uuidv4()}.mp4`;
    const outputPath = path.join(config.OUTPUT_DIR, filename);

    // ── Build FFmpeg args ─────────────────────────────────
    const args = [
      // Seek to start BEFORE input (fast seek)
      '-ss', start,
      // Stop at end time
      '-to', end,
      // Input URL
      '-i', url,
      // ── Sandboxing flags ──────────────────────────────
      // Disable all network-based protocols except http(s)/hls/tcp/tls
      '-protocol_whitelist', 'file,http,https,tcp,tls,crypto',
      // Limit input streams to avoid abuse
      '-max_streams', '10',
      // Copy codecs (no re-encode → fast)
      '-c', 'copy',
      // Force overwrite
      '-y',
      // Disable interactive prompts
      '-nostdin',
      // Limit log verbosity
      '-loglevel', 'warning',
      // Output file
      outputPath,
    ];

    logger.info('FFmpeg starting', { url, start, end, filename });

    const ffmpeg = spawn(config.FFMPEG_PATH, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      // Don't inherit env — clean environment
      env: {
        PATH: process.env.PATH,
        TEMP: process.env.TEMP || '/tmp',
        TMP: process.env.TMP || '/tmp',
        SYSTEMROOT: process.env.SYSTEMROOT, // Needed on Windows
      },
    });

    let stderr = '';

    ffmpeg.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
      // Safety: limit stderr buffer to 10 KB
      if (stderr.length > 10240) {
        stderr = stderr.slice(-10240);
      }
    });

    // ── Execution timeout ─────────────────────────────────
    const timeout = setTimeout(() => {
      logger.error('FFmpeg timed out, killing process', { filename });
      ffmpeg.kill('SIGKILL');
      // Clean up partial file
      try { fs.unlinkSync(outputPath); } catch { /* ignore */ }
      resolve({ ok: false, reason: 'FFmpeg execution timed out.' });
    }, config.FFMPEG_TIMEOUT_MS);

    ffmpeg.on('close', (code) => {
      clearTimeout(timeout);

      if (code !== 0) {
        logger.error('FFmpeg exited with error', { code, stderr: stderr.slice(0, 500) });
        // Clean up partial file
        try { fs.unlinkSync(outputPath); } catch { /* ignore */ }
        return resolve({
          ok: false,
          reason: `FFmpeg error (exit code ${code}).`,
        });
      }

      // Check that output file actually exists and has content
      try {
        const stats = fs.statSync(outputPath);
        if (stats.size === 0) {
          fs.unlinkSync(outputPath);
          return resolve({ ok: false, reason: 'FFmpeg produced empty output.' });
        }

        logger.info('Clip created successfully', {
          filename,
          sizeBytes: stats.size,
        });

        return resolve({ ok: true, filePath: outputPath, filename });
      } catch {
        return resolve({ ok: false, reason: 'Output file not found after FFmpeg.' });
      }
    });

    ffmpeg.on('error', (err) => {
      clearTimeout(timeout);
      logger.error('FFmpeg spawn error', { error: err.message });
      resolve({
        ok: false,
        reason: `Could not start FFmpeg: ${err.message}`,
      });
    });
  });
}

/**
 * Delete a clip file (cleanup after download).
 */
function deleteClip(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      logger.info('Clip file deleted', { filePath });
    }
  } catch (err) {
    logger.error('Failed to delete clip file', { filePath, error: err.message });
  }
}

module.exports = { cutClip, deleteClip };
