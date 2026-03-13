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

// ── Concurrency limiter (prevent resource exhaustion) ────────
const MAX_CONCURRENT = 3;
let activeProcesses = 0;

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
    // ── Concurrency check ──────────────────────────────
    if (activeProcesses >= MAX_CONCURRENT) {
      logger.warn('FFmpeg concurrency limit reached', { active: activeProcesses });
      return resolve({ ok: false, reason: 'Server is busy. Please try again in a moment.' });
    }
    activeProcesses++;

    const filename = `${uuidv4()}.mp4`;
    const outputPath = path.join(config.OUTPUT_DIR, filename);

    // Sanitize URL for logging (strip control chars that could mess up logs)
    const safeLogUrl = url.replace(/[\x00-\x1f\x7f]/g, '?');

    // ── Build FFmpeg args ─────────────────────────────
    const args = [
      // Seek to start BEFORE input (fast seek)
      '-ss', start,
      // Stop at end time
      '-to', end,
      // Input URL
      '-i', url,
      // ── Sandboxing flags ──────────────────────────
      // Whitelist: only allow these protocols (no file!)
      '-protocol_whitelist', 'http,https,tcp,tls,crypto',
      // Blacklist: explicitly block dangerous protocols as belt-and-suspenders
      '-protocol_blacklist', 'concat,data,file,subfile,pipe,cache,fd,gopher,ftp,rtp,srtp,udp',
      // Limit input streams to avoid abuse
      '-max_streams', '10',
      // Only copy video + audio streams (reject subtitles, data, attachments
      // which could carry malware payloads)
      '-map', '0:v?',
      '-map', '0:a?',
      '-dn',            // disable data streams
      '-sn',            // disable subtitle streams
      // Copy codecs (no re-encode → fast)
      '-c', 'copy',
      // FFmpeg-native file size limit (belt-and-suspenders with polling monitor)
      '-fs', String(config.MAX_FILE_SIZE_BYTES),
      // Force overwrite
      '-y',
      // Disable interactive prompts
      '-nostdin',
      // Limit log verbosity
      '-loglevel', 'warning',
      // Output file
      outputPath,
    ];

    logger.info('FFmpeg starting', { url: safeLogUrl, start, end, filename });

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

    // ── Output file size monitor (prevent disk-filling) ────
    const sizeCheckInterval = setInterval(() => {
      try {
        const stats = fs.statSync(outputPath);
        if (stats.size > config.MAX_FILE_SIZE_BYTES) {
          logger.error('Output file too large, killing FFmpeg', {
            filename,
            sizeBytes: stats.size,
            limitBytes: config.MAX_FILE_SIZE_BYTES,
          });
          ffmpeg.kill('SIGKILL');
          clearInterval(sizeCheckInterval);
          clearTimeout(timeout);
          try { fs.unlinkSync(outputPath); } catch { /* ignore */ }
          resolve({ ok: false, reason: 'Output file exceeded size limit.' });
        }
      } catch { /* file doesn't exist yet, ignore */ }
    }, 2000); // check every 2 seconds

    ffmpeg.on('close', (code) => {
      clearTimeout(timeout);
      clearInterval(sizeCheckInterval);
      activeProcesses--;

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
      clearInterval(sizeCheckInterval);
      activeProcesses--;
      logger.error('FFmpeg spawn error', { error: err.message });
      resolve({
        ok: false,
        reason: 'Could not start FFmpeg.',
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
