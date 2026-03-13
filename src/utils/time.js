// ─────────────────────────────────────────────────────────────
// Time-string helpers for HH:MM:SS parsing / validation.
// ─────────────────────────────────────────────────────────────

const TIME_REGEX = /^(\d{1,2}):(\d{2}):(\d{2})$/;

/**
 * Parse a "HH:MM:SS" string into total seconds.
 * Returns null if format is invalid.
 */
function parseTimestamp(ts) {
  if (typeof ts !== 'string') return null;

  const match = ts.match(TIME_REGEX);
  if (!match) return null;

  const hours = parseInt(match[1], 10);
  const mins  = parseInt(match[2], 10);
  const secs  = parseInt(match[3], 10);

  if (mins > 59 || secs > 59) return null;
  if (hours < 0 || mins < 0 || secs < 0) return null;

  return hours * 3600 + mins * 60 + secs;
}

/**
 * Validate that start < end, and the duration is within the allowed max.
 */
function validateTimeRange(startStr, endStr, maxDurationSeconds) {
  const startSec = parseTimestamp(startStr);
  const endSec   = parseTimestamp(endStr);

  if (startSec === null) return { ok: false, reason: 'Invalid start time format. Use HH:MM:SS.' };
  if (endSec === null)   return { ok: false, reason: 'Invalid end time format. Use HH:MM:SS.' };
  if (endSec <= startSec) return { ok: false, reason: 'end_time must be after start_time.' };

  const duration = endSec - startSec;
  if (duration > maxDurationSeconds) {
    return { ok: false, reason: `Clip duration (${duration}s) exceeds maximum allowed (${maxDurationSeconds}s).` };
  }

  return { ok: true, startSec, endSec, duration };
}

module.exports = { parseTimestamp, validateTimeRange };
