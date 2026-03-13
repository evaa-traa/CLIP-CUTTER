# 🎬 Clip Cutter — Secure Video Clip Extraction Service

A hardened Node.js backend that accepts a direct media URL + timestamps and returns a clipped video segment using FFmpeg. **Security is the #1 priority.**

---

## ⚡ Quick Start

```bash
# 1. Install dependencies
npm install

# 2. (Required) Install FFmpeg — must be on your PATH
#    Windows: https://www.gyan.dev/ffmpeg/builds/
#    Linux:   sudo apt install ffmpeg
#    macOS:   brew install ffmpeg

# 3. Start the server
npm start

# Or in dev mode (auto-restart on file changes)
npm run dev
```

The server starts on `http://localhost:3000` by default.

---

## 📡 API Endpoints

### `GET /health`

Health check — also verifies FFmpeg availability.

```json
{
  "status": "ok",
  "service": "clip-cutter",
  "ffmpeg": "available",
  "uptime": 42,
  "timestamp": "2026-03-13T00:00:00.000Z"
}
```

### `POST /clip`

Cut a clip from a direct video stream.

**Request:**

```json
{
  "url": "https://cdn.example.com/stream/index.m3u8",
  "start": "00:10:10",
  "end": "00:10:40"
}
```

**Success:** Returns the `.mp4` file as a download.

**Failure:**

```json
{
  "status": "rejected",
  "reason": "invalid media URL"
}
```

---

## 🛡️ Security Layers

| # | Protection | Details |
|---|-----------|---------|
| 1 | **Extension Whitelist** | Only `.m3u8`, `.mp4`, `.webm`, `.ts` |
| 2 | **Domain Blocklist** | Rejects known piracy/streaming site domains |
| 3 | **Path Segment Blocklist** | Rejects URLs containing `/movie/`, `/download/`, `/embed/`, `/watch/` |
| 4 | **MIME Type Validation** | HEAD request verifies `video/*` or HLS content types |
| 5 | **HTML/JS/JSON Rejection** | Explicitly blocks `text/html`, `application/javascript`, `application/json` |
| 6 | **Redirect Limiting** | Max 2 redirects, then rejected |
| 7 | **SSRF Prevention** | DNS resolution check — blocks private IPs, localhost, internal networks |
| 8 | **File Size Guard** | Aborts if content > 500 MB |
| 9 | **Duration Limit** | Max 90 seconds per clip |
| 10 | **FFmpeg Sandboxing** | Protocol whitelist, limited streams, clean env, execution timeout |
| 11 | **UUID Filenames** | Output filenames are random UUIDs — never user input |
| 12 | **Rate Limiting** | 5 requests per minute per IP |
| 13 | **Input Sanitisation** | Type + length validation on all fields |
| 14 | **Helmet Headers** | Security HTTP headers (CSP, HSTS, X-Frame-Options, etc.) |
| 15 | **Body Size Limit** | Max 1 MB JSON body |

---

## 📁 Project Structure

```
CLIP CUTTER/
├── src/
│   ├── app.js                    # Express server assembly
│   ├── config/
│   │   └── index.js              # Centralised configuration
│   ├── middleware/
│   │   ├── rateLimiter.js        # 5 req/min rate limiter
│   │   └── inputValidator.js     # Request body validation
│   ├── routes/
│   │   ├── clip.js               # POST /clip handler
│   │   └── health.js             # GET /health handler
│   ├── services/
│   │   └── ffmpegService.js      # Sandboxed FFmpeg execution
│   ├── utils/
│   │   ├── logger.js             # Winston structured logger
│   │   └── time.js               # HH:MM:SS parsing
│   └── validators/
│       └── urlValidator.js       # URL/domain/MIME/SSRF validation
├── tests/
│   └── test.js                   # Unit tests (24 tests)
├── clips/                        # Output clips (auto-created, gitignored)
├── logs/                         # Log files (auto-created, gitignored)
├── .env.example                  # Environment variables template
├── .gitignore
├── package.json
└── README.md
```

---

## ⚙️ Configuration

All tunables are in `src/config/index.js`. Override via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `FFMPEG_PATH` | `ffmpeg` | Path to FFmpeg binary |
| `CORS_ORIGIN` | `*` | Allowed CORS origin (tighten in production) |
| `LOG_LEVEL` | `info` | Winston log level |

---

## 🧪 Testing

```bash
npm test
```

Runs 24 unit tests covering:
- Time parsing & validation
- URL format validation
- Private IP / SSRF detection

---

## 📊 Logging

Logs are written to the `logs/` directory:

| File | Contents |
|------|----------|
| `combined.log` | All log entries |
| `error.log` | Errors only |
| `rejected.log` | Rejected requests with reasons |

Logs rotate at 5 MB with 5 file history.

---

## 🧾 Request Flow

```
POST /clip
   │
   ├── 1. Rate Limiter (5 req/min per IP)
   ├── 2. Input Validation (fields, types, lengths)
   ├── 3. URL Format Check (protocol, extension)
   ├── 4. Domain Safety Check (SSRF, blocklists)
   ├── 5. HEAD Request (MIME type, size, redirects)
   ├── 6. Timestamp Validation (format, range, duration)
   ├── 7. FFmpeg Execution (sandboxed, timeout)
   ├── 8. File Delivery → client download
   └── 9. Cleanup (delete temp file)
```

---

## ⚠️ Requirements

- **Node.js** ≥ 18.0.0
- **FFmpeg** installed and on `PATH` (or set `FFMPEG_PATH`)
