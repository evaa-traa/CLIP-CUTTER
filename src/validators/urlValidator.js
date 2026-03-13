// ─────────────────────────────────────────────────────────────
// URL & Network security validators.
//
// Covers:
//   • Extension whitelist
//   • Domain / SSRF blocklist
//   • MIME type validation via HEAD request
//   • Redirect-chain enforcement
//   • File-size guard
// ─────────────────────────────────────────────────────────────

const { URL } = require('url');
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');
const path = require('path');
const config = require('../config');
const logger = require('../utils/logger');

// ── Blocked domain keywords (piracy / streaming sites) ──────
const BLOCKED_DOMAIN_KEYWORDS = [
  'vegamovies', 'hdmovie', 'filmyzilla', 'piratebay', 'yts.',
  'torrent', 'fmovies', 'putlocker', '123movies', 'gomovies',
  'solarmovies', 'openload', 'streamtape', 'mixdrop', 'doodstream',
];

// ── Blocked URL path segments ───────────────────────────────
const BLOCKED_PATH_SEGMENTS = [
  '/movie/', '/download/', '/embed/', '/watch/',
  '/series/', '/episode/',
];

// ── Private IP ranges (SSRF prevention) ─────────────────────
const PRIVATE_IP_RANGES = [
  { start: '10.0.0.0',     end: '10.255.255.255' },
  { start: '172.16.0.0',   end: '172.31.255.255' },
  { start: '192.168.0.0',  end: '192.168.255.255' },
  { start: '127.0.0.0',    end: '127.255.255.255' },
  { start: '169.254.0.0',  end: '169.254.255.255' },
  { start: '0.0.0.0',      end: '0.255.255.255' },
];

function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isPrivateIp(ip) {
  if (!net.isIPv4(ip)) return false;
  const ipLong = ipToLong(ip);
  return PRIVATE_IP_RANGES.some(
    (r) => ipLong >= ipToLong(r.start) && ipLong <= ipToLong(r.end)
  );
}

// ─── 1. Basic URL syntax + extension check ──────────────────
function validateUrlFormat(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, reason: 'Malformed URL.' };
  }

  // Only http(s) allowed
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, reason: 'Only HTTP/HTTPS URLs are allowed.' };
  }

  // Extract extension (ignore query string)
  const ext = path.extname(parsed.pathname).toLowerCase();
  if (!config.ALLOWED_EXTENSIONS.includes(ext)) {
    return {
      ok: false,
      reason: `File extension "${ext || '(none)'}" is not allowed. Allowed: ${config.ALLOWED_EXTENSIONS.join(', ')}`,
    };
  }

  return { ok: true, parsed, ext };
}

// ─── 2. Domain safety (SSRF + piracy keywords) ─────────────
async function validateDomain(parsed) {
  const hostname = parsed.hostname.toLowerCase();

  // Reject raw IPs that are private
  if (net.isIPv4(hostname) || net.isIPv6(hostname)) {
    if (net.isIPv4(hostname) && isPrivateIp(hostname)) {
      return { ok: false, reason: 'Private/internal IP addresses are not allowed.' };
    }
    if (hostname === '::1' || hostname === '0:0:0:0:0:0:0:1') {
      return { ok: false, reason: 'Loopback addresses are not allowed.' };
    }
  }

  // Reject localhost variants
  if (hostname === 'localhost' || hostname.endsWith('.local')) {
    return { ok: false, reason: 'localhost is not allowed.' };
  }

  // Reject known piracy / streaming site domains
  for (const keyword of BLOCKED_DOMAIN_KEYWORDS) {
    if (hostname.includes(keyword)) {
      return {
        ok: false,
        reason: `Domain contains blocked keyword: "${keyword}".`,
      };
    }
  }

  // Reject blocked path segments
  const lowerPath = parsed.pathname.toLowerCase();
  for (const segment of BLOCKED_PATH_SEGMENTS) {
    if (lowerPath.includes(segment)) {
      return {
        ok: false,
        reason: `URL path contains blocked segment: "${segment}".`,
      };
    }
  }

  // DNS resolution check — make sure resolved IPs are not private
  try {
    const addresses = await new Promise((resolve, reject) => {
      dns.resolve4(hostname, (err, addrs) => {
        if (err) reject(err);
        else resolve(addrs);
      });
    });

    for (const addr of addresses) {
      if (isPrivateIp(addr)) {
        return {
          ok: false,
          reason: `Domain resolves to private IP (${addr}). SSRF blocked.`,
        };
      }
    }
  } catch (dnsErr) {
    // If DNS resolution fails, we still allow if hostname is an IP
    if (!net.isIPv4(hostname)) {
      return { ok: false, reason: `DNS resolution failed for "${hostname}".` };
    }
  }

  return { ok: true };
}

// ─── 3. HEAD request — MIME type + size + redirect check ────
function validateContentType(url) {
  return new Promise((resolve) => {
    let redirectCount = 0;

    function doHead(targetUrl) {
      let parsed;
      try {
        parsed = new URL(targetUrl);
      } catch {
        return resolve({ ok: false, reason: 'Invalid URL during redirect.' });
      }

      const transport = parsed.protocol === 'https:' ? https : http;

      const req = transport.request(
        targetUrl,
        {
          method: 'HEAD',
          timeout: config.HEAD_REQUEST_TIMEOUT_MS,
          // Disable auto-follow so we count redirects manually
          headers: {
            'User-Agent': 'ClipCutter/1.0 (Validator)',
          },
        },
        (res) => {
          // ── Handle redirects ────────────────────────────
          if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
            redirectCount++;
            if (redirectCount > config.MAX_REDIRECTS) {
              return resolve({
                ok: false,
                reason: `Too many redirects (>${config.MAX_REDIRECTS}).`,
              });
            }
            const location = res.headers.location;
            if (!location) {
              return resolve({ ok: false, reason: 'Redirect without Location header.' });
            }
            // Resolve relative redirects
            const nextUrl = new URL(location, targetUrl).href;
            return doHead(nextUrl);
          }

          if (res.statusCode < 200 || res.statusCode >= 400) {
            return resolve({
              ok: false,
              reason: `HEAD request returned status ${res.statusCode}.`,
            });
          }

          // ── Content-Type check ──────────────────────────
          const rawCT = (res.headers['content-type'] || '').toLowerCase();
          const contentType = rawCT.split(';')[0].trim();

          // Block explicit bad types
          for (const blocked of config.BLOCKED_CONTENT_TYPES) {
            if (contentType.startsWith(blocked)) {
              return resolve({
                ok: false,
                reason: `Content-Type "${contentType}" is not a video stream. This looks like a website page.`,
              });
            }
          }

          // Must match at least one allowed type
          const isAllowed = config.ALLOWED_CONTENT_TYPES.some(
            (allowed) => contentType.startsWith(allowed)
          );

          // For .m3u8 some servers return text/plain, we allow that specifically
          if (!isAllowed && contentType !== 'text/plain' && contentType !== 'application/octet-stream' && contentType !== 'binary/octet-stream') {
            return resolve({
              ok: false,
              reason: `Content-Type "${contentType}" is not in the allowed list.`,
            });
          }

          // ── File-size check ─────────────────────────────
          const contentLength = parseInt(res.headers['content-length'], 10);
          if (!isNaN(contentLength) && contentLength > config.MAX_FILE_SIZE_BYTES) {
            return resolve({
              ok: false,
              reason: `File size (~${(contentLength / 1024 / 1024).toFixed(1)} MB) exceeds the ${config.MAX_FILE_SIZE_BYTES / 1024 / 1024} MB limit.`,
            });
          }

          resolve({ ok: true, contentType, contentLength });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, reason: 'HEAD request timed out.' });
      });

      req.on('error', (err) => {
        resolve({ ok: false, reason: `HEAD request failed: ${err.message}` });
      });

      req.end();
    }

    doHead(url);
  });
}

// ─── Orchestrator — run all checks in sequence ──────────────
async function validateUrl(rawUrl) {
  // Step 1: format + extension
  const fmt = validateUrlFormat(rawUrl);
  if (!fmt.ok) {
    logger.warn('URL rejected (format)', { url: rawUrl, reason: fmt.reason });
    return fmt;
  }

  // Step 2: domain / SSRF
  const dom = await validateDomain(fmt.parsed);
  if (!dom.ok) {
    logger.warn('URL rejected (domain)', { url: rawUrl, reason: dom.reason });
    return dom;
  }

  // Step 3: HEAD — content-type, size, redirects
  const ct = await validateContentType(rawUrl);
  if (!ct.ok) {
    logger.warn('URL rejected (content-type)', { url: rawUrl, reason: ct.reason });
    return ct;
  }

  return { ok: true, contentType: ct.contentType, contentLength: ct.contentLength };
}

module.exports = {
  validateUrl,
  validateUrlFormat,
  validateDomain,
  validateContentType,
  isPrivateIp,
};
