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

// ── Cloud metadata hostnames (SSRF targets) ─────────────────
const CLOUD_METADATA_HOSTS = [
  'metadata.google.internal',
  'metadata.google',
  'kubernetes.default.svc',
  'kubernetes.default',
];

// ── Characters that FFmpeg interprets specially ─────────────
// Pipe = concat protocol, backtick/semicolon = shell injection if misused
const DANGEROUS_URL_CHARS = /[|`;&$(){}\[\]!#]/;

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

/**
 * Check if an IPv4 address is private/internal.
 */
function isPrivateIPv4(ip) {
  if (!net.isIPv4(ip)) return false;
  const ipLong = ipToLong(ip);
  return PRIVATE_IP_RANGES.some(
    (r) => ipLong >= ipToLong(r.start) && ipLong <= ipToLong(r.end)
  );
}

/**
 * Check if an IPv6 address is private/internal.
 * Covers: loopback (::1), link-local (fe80::), unique-local (fc00::/fd00::),
 * IPv4-mapped (::ffff:x.x.x.x), and IPv4-compatible (::x.x.x.x).
 */
function isPrivateIPv6(ip) {
  if (!net.isIPv6(ip)) return false;
  const lower = ip.toLowerCase().replace(/^\[|\]$/g, '');

  // Loopback
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // Unspecified
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  // Link-local
  if (lower.startsWith('fe80:')) return true;
  // Unique-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;

  // IPv4-mapped IPv6 (::ffff:10.0.0.1)
  const v4Mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Mapped && isPrivateIPv4(v4Mapped[1])) return true;

  // IPv4-compatible IPv6 (::10.0.0.1)
  const v4Compat = lower.match(/^::(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Compat && isPrivateIPv4(v4Compat[1])) return true;

  return false;
}

/**
 * Check if any IP (v4 or v6) is private.
 */
function isPrivateIp(ip) {
  return isPrivateIPv4(ip) || isPrivateIPv6(ip);
}

// ─── 1. Basic URL syntax + extension check ──────────────────
function validateUrlFormat(rawUrl) {
  // Block null bytes (parser confusion attacks)
  if (rawUrl.includes('\0') || rawUrl.includes('%00')) {
    return { ok: false, reason: 'URL contains invalid characters.' };
  }

  // Block FFmpeg-dangerous characters (concat protocol, shell chars)
  if (DANGEROUS_URL_CHARS.test(rawUrl)) {
    return { ok: false, reason: 'URL contains disallowed characters.' };
  }

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

  // Block URLs with embedded credentials (user:pass@host)
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'URLs with credentials are not allowed.' };
  }

  // Block punycode / IDN homograph attacks (e.g. xn--ggle-55da.com masking as google.com)
  if (parsed.hostname.startsWith('xn--') || parsed.hostname.includes('.xn--')) {
    return { ok: false, reason: 'Internationalized domain names are not allowed.' };
  }

  // Extract extension (ignore query string)
  const ext = path.extname(parsed.pathname).toLowerCase();
  if (!config.ALLOWED_EXTENSIONS.includes(ext)) {
    return {
      ok: false,
      reason: `File extension not allowed. Supported: ${config.ALLOWED_EXTENSIONS.join(', ')}`,
    };
  }

  return { ok: true, parsed, ext };
}

// ─── 2. Domain safety (SSRF + piracy keywords) ─────────────
async function validateDomain(parsed) {
  const hostname = parsed.hostname.toLowerCase();

  // Reject raw IPs that are private (v4 + v6)
  if (net.isIPv4(hostname) && isPrivateIp(hostname)) {
    return { ok: false, reason: 'URL not allowed — target address is restricted.' };
  }
  if (net.isIPv6(hostname) && isPrivateIp(hostname)) {
    return { ok: false, reason: 'URL not allowed — target address is restricted.' };
  }

  // Reject localhost variants
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.localhost')) {
    return { ok: false, reason: 'URL not allowed — target address is restricted.' };
  }

  // Reject cloud metadata endpoints (AWS/GCP/Azure/k8s)
  for (const metaHost of CLOUD_METADATA_HOSTS) {
    if (hostname === metaHost || hostname.endsWith('.' + metaHost)) {
      logger.warn('Cloud metadata SSRF blocked', { hostname });
      return { ok: false, reason: 'URL not allowed — target address is restricted.' };
    }
  }

  // Reject known piracy / streaming site domains
  for (const keyword of BLOCKED_DOMAIN_KEYWORDS) {
    if (hostname.includes(keyword)) {
      return { ok: false, reason: 'This domain is not allowed.' };
    }
  }

  // Reject blocked path segments
  const lowerPath = parsed.pathname.toLowerCase();
  for (const segment of BLOCKED_PATH_SEGMENTS) {
    if (lowerPath.includes(segment)) {
      return { ok: false, reason: 'This URL path is not allowed.' };
    }
  }

  // DNS resolution check — make sure ALL resolved IPs (v4 + v6) are not private
  try {
    // Resolve both A and AAAA records
    const [v4Addrs, v6Addrs] = await Promise.all([
      new Promise((resolve) => {
        dns.resolve4(hostname, (err, addrs) => resolve(err ? [] : addrs));
      }),
      new Promise((resolve) => {
        dns.resolve6(hostname, (err, addrs) => resolve(err ? [] : addrs));
      }),
    ]);

    const allAddrs = [...v4Addrs, ...v6Addrs];

    if (allAddrs.length === 0 && !net.isIPv4(hostname) && !net.isIPv6(hostname)) {
      return { ok: false, reason: 'DNS resolution failed.' };
    }

    for (const addr of allAddrs) {
      if (isPrivateIp(addr)) {
        logger.warn('SSRF blocked: domain resolves to private IP', { hostname, addr });
        return {
          ok: false,
          reason: 'URL not allowed — target address is restricted.',
        };
      }
    }
  } catch (dnsErr) {
    if (!net.isIPv4(hostname) && !net.isIPv6(hostname)) {
      return { ok: false, reason: 'DNS resolution failed.' };
    }
  }

  return { ok: true };
}

// ─── 3. Content validation via HEAD with GET fallback ───────
// Many streaming CDNs don't support HEAD (return 404/405).
// We fall back to a partial GET (Range: bytes=0-1023) which
// most servers handle correctly.
// ─────────────────────────────────────────────────────────────

function makeRequest(targetUrl, method, extraHeaders = {}) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return resolve({ ok: false, reason: 'Invalid URL.' });
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return resolve({ ok: false, reason: 'Only HTTP/HTTPS URLs are allowed.' });
    }

    const transport = parsed.protocol === 'https:' ? https : http;

    const req = transport.request(
      targetUrl,
      {
        method,
        timeout: config.HEAD_REQUEST_TIMEOUT_MS,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          ...extraHeaders,
        },
      },
      (res) => {
        // Consume the body to free up the socket
        res.resume();
        resolve({
          ok: true,
          statusCode: res.statusCode,
          headers: res.headers,
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, reason: 'Request timed out.' });
    });

    req.on('error', (err) => {
      logger.warn('Request error', { url: targetUrl, method, error: err.message });
      resolve({ ok: false, reason: 'Could not reach the URL.' });
    });

    req.end();
  });
}

function validateContentType(url, referer) {
  return new Promise(async (resolve) => {
    let redirectCount = 0;
    let currentUrl = url;

    // Build referer header if provided
    const refHeaders = referer ? { 'Referer': referer, 'Origin': new URL(referer).origin } : {};

    // Follow redirects manually (with SSRF checks)
    while (true) {
      const result = await makeRequest(currentUrl, 'HEAD', refHeaders);
      if (!result.ok) return resolve(result);

      const { statusCode, headers } = result;

      // Handle redirects
      if ([301, 302, 303, 307, 308].includes(statusCode)) {
        redirectCount++;
        if (redirectCount > config.MAX_REDIRECTS) {
          return resolve({ ok: false, reason: 'Too many redirects.' });
        }
        const location = headers.location;
        if (!location) {
          return resolve({ ok: false, reason: 'Redirect without Location header.' });
        }
        const nextUrl = new URL(location, currentUrl).href;

        // SSRF check on redirect target
        let nextParsed;
        try { nextParsed = new URL(nextUrl); } catch {
          return resolve({ ok: false, reason: 'Invalid redirect URL.' });
        }
        const redirectDomCheck = await validateDomain(nextParsed);
        if (!redirectDomCheck.ok) {
          logger.warn('Redirect SSRF blocked', { from: currentUrl, to: nextUrl });
          return resolve({ ok: false, reason: 'Redirect target is not allowed.' });
        }
        currentUrl = nextUrl;
        continue;
      }

      // HEAD succeeded — validate the response
      if (statusCode >= 200 && statusCode < 400) {
        return resolve(validateResponse(headers));
      }

      // HEAD failed (404, 405, 403, etc.) — try GET fallback
      logger.info('HEAD returned ' + statusCode + ', trying GET fallback', { url: currentUrl });

      const getResult = await makeRequest(currentUrl, 'GET', {
        'Range': 'bytes=0-1023',  // Only fetch first 1 KB
        ...refHeaders,
      });

      if (!getResult.ok) return resolve(getResult);

      if ([301, 302, 303, 307, 308].includes(getResult.statusCode)) {
        const loc = getResult.headers.location;
        if (!loc) return resolve({ ok: false, reason: 'Redirect without Location header.' });
        const nextUrl = new URL(loc, currentUrl).href;
        let np; try { np = new URL(nextUrl); } catch {
          return resolve({ ok: false, reason: 'Invalid redirect URL.' });
        }
        const dc = await validateDomain(np);
        if (!dc.ok) return resolve({ ok: false, reason: 'Redirect target is not allowed.' });

        const getResult2 = await makeRequest(nextUrl, 'GET', { 'Range': 'bytes=0-1023', ...refHeaders });
        if (!getResult2.ok) return resolve(getResult2);
        if (getResult2.statusCode >= 200 && getResult2.statusCode < 400) {
          return resolve(validateResponse(getResult2.headers));
        }
        return resolve({ ok: false, reason: 'Server returned status ' + getResult2.statusCode + '.' });
      }

      if (getResult.statusCode >= 200 && getResult.statusCode < 400) {
        return resolve(validateResponse(getResult.headers));
      }

      return resolve({
        ok: false,
        reason: 'Server returned status ' + getResult.statusCode + ' for both HEAD and GET requests.',
      });
    }
  });
}

// Shared response header validator (used by both HEAD and GET paths)
function validateResponse(headers) {
  const rawCT = (headers['content-type'] || '').toLowerCase();
  const contentType = rawCT.split(';')[0].trim();

  // Block explicit bad types
  for (const blocked of config.BLOCKED_CONTENT_TYPES) {
    if (contentType.startsWith(blocked)) {
      return {
        ok: false,
        reason: 'Content-Type "' + contentType + '" is not a video stream.',
      };
    }
  }

  // Must match at least one allowed type
  const isAllowed = config.ALLOWED_CONTENT_TYPES.some(
    (allowed) => contentType.startsWith(allowed)
  );

  // For .m3u8 some servers return text/plain or octet-stream
  if (!isAllowed && contentType !== 'text/plain' && contentType !== 'application/octet-stream' && contentType !== 'binary/octet-stream' && contentType !== '') {
    return {
      ok: false,
      reason: 'Content-Type "' + contentType + '" is not in the allowed list.',
    };
  }

  // File-size check
  const contentLength = parseInt(headers['content-length'], 10);
  if (!isNaN(contentLength) && contentLength > config.MAX_FILE_SIZE_BYTES) {
    return {
      ok: false,
      reason: 'File too large. Maximum allowed is ' + (config.MAX_FILE_SIZE_BYTES / 1024 / 1024) + ' MB.',
    };
  }

  return { ok: true, contentType, contentLength };
}

// ─── Orchestrator — run all checks in sequence ──────────────
async function validateUrl(rawUrl, referer) {
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
  const ct = await validateContentType(rawUrl, referer);
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
