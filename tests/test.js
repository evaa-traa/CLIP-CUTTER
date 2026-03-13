// ─────────────────────────────────────────────────────────────
// Unit tests — run with: node tests/test.js
//
// Uses only Node.js built-in assert (zero test-framework deps).
// ─────────────────────────────────────────────────────────────

const assert = require('assert');
const { parseTimestamp, validateTimeRange } = require('../src/utils/time');
const {
  validateUrlFormat,
  isPrivateIp,
} = require('../src/validators/urlValidator');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌  ${name}`);
    console.error(`      ${err.message}`);
    failed++;
  }
}

console.log('\n═══════════════════════════════════════');
console.log('  CLIP CUTTER — Unit Tests');
console.log('═══════════════════════════════════════\n');

// ─── Time parsing ────────────────────────────────────────────
console.log('── Time Parsing ──');

test('parseTimestamp: valid "00:10:10" → 610', () => {
  assert.strictEqual(parseTimestamp('00:10:10'), 610);
});

test('parseTimestamp: valid "01:30:00" → 5400', () => {
  assert.strictEqual(parseTimestamp('01:30:00'), 5400);
});

test('parseTimestamp: valid "00:00:00" → 0', () => {
  assert.strictEqual(parseTimestamp('00:00:00'), 0);
});

test('parseTimestamp: invalid format "10:10" → null', () => {
  assert.strictEqual(parseTimestamp('10:10'), null);
});

test('parseTimestamp: invalid minutes "00:99:00" → null', () => {
  assert.strictEqual(parseTimestamp('00:99:00'), null);
});

test('parseTimestamp: non-string input → null', () => {
  assert.strictEqual(parseTimestamp(12345), null);
});

// ─── Time range validation ───────────────────────────────────
console.log('\n── Time Range Validation ──');

test('validateTimeRange: 30s clip within 90s limit → ok', () => {
  const r = validateTimeRange('00:10:10', '00:10:40', 90);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.duration, 30);
});

test('validateTimeRange: 91s clip exceeds 90s limit → rejected', () => {
  const r = validateTimeRange('00:00:00', '00:01:31', 90);
  assert.strictEqual(r.ok, false);
  assert.ok(r.reason.includes('exceeds'));
});

test('validateTimeRange: end before start → rejected', () => {
  const r = validateTimeRange('00:10:40', '00:10:10', 90);
  assert.strictEqual(r.ok, false);
});

test('validateTimeRange: same start and end → rejected', () => {
  const r = validateTimeRange('00:10:10', '00:10:10', 90);
  assert.strictEqual(r.ok, false);
});

// ─── URL format validation ───────────────────────────────────
console.log('\n── URL Format Validation ──');

test('validateUrlFormat: valid .mp4 URL → ok', () => {
  const r = validateUrlFormat('https://cdn.example.com/video/clip.mp4');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.ext, '.mp4');
});

test('validateUrlFormat: valid .m3u8 URL → ok', () => {
  const r = validateUrlFormat('https://stream.example.com/live/index.m3u8');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.ext, '.m3u8');
});

test('validateUrlFormat: valid .webm URL → ok', () => {
  const r = validateUrlFormat('https://cdn.example.com/v/file.webm');
  assert.strictEqual(r.ok, true);
});

test('validateUrlFormat: valid .ts URL → ok', () => {
  const r = validateUrlFormat('https://cdn.example.com/seg/chunk.ts');
  assert.strictEqual(r.ok, true);
});

test('validateUrlFormat: .html URL → rejected', () => {
  const r = validateUrlFormat('https://example.com/page.html');
  assert.strictEqual(r.ok, false);
});

test('validateUrlFormat: no extension → rejected', () => {
  const r = validateUrlFormat('https://example.com/video');
  assert.strictEqual(r.ok, false);
});

test('validateUrlFormat: ftp protocol → rejected', () => {
  const r = validateUrlFormat('ftp://example.com/video.mp4');
  assert.strictEqual(r.ok, false);
});

test('validateUrlFormat: malformed URL → rejected', () => {
  const r = validateUrlFormat('not a url at all');
  assert.strictEqual(r.ok, false);
});

// ─── SSRF / Private IP ──────────────────────────────────────
console.log('\n── SSRF / Private IP Detection ──');

test('isPrivateIp: 127.0.0.1 → true', () => {
  assert.strictEqual(isPrivateIp('127.0.0.1'), true);
});

test('isPrivateIp: 10.0.0.5 → true', () => {
  assert.strictEqual(isPrivateIp('10.0.0.5'), true);
});

test('isPrivateIp: 192.168.1.1 → true', () => {
  assert.strictEqual(isPrivateIp('192.168.1.1'), true);
});

test('isPrivateIp: 172.16.0.1 → true', () => {
  assert.strictEqual(isPrivateIp('172.16.0.1'), true);
});

test('isPrivateIp: 8.8.8.8 → false', () => {
  assert.strictEqual(isPrivateIp('8.8.8.8'), false);
});

test('isPrivateIp: 203.0.113.1 → false', () => {
  assert.strictEqual(isPrivateIp('203.0.113.1'), false);
});

// ─── Summary ─────────────────────────────────────────────────
console.log('\n═══════════════════════════════════════');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('═══════════════════════════════════════\n');

process.exit(failed > 0 ? 1 : 0);
