# Phishy

A professional web application that detects and scans URLs for phishing and malicious links. Built with Next.js 15, TypeScript, and a comprehensive suite of detection algorithms.

## Features

### Detection Capabilities

1. **Homoglyph & Punycode Detection**
   - Identifies visually similar Unicode characters used to impersonate legitimate domains
   - Detects IDN (Internationalized Domain Names) attacks
   - Flags Cyrillic, Greek, and other non-ASCII character substitutions

2. **Typosquatting Analysis**
   - Uses Levenshtein distance to detect domains that are one or two characters away from popular brands
   - Compares against a curated list of 40+ high-value targets

3. **Structural Red Flags**
   - Raw IP addresses in hostname
   - Excessive subdomain depth (≥4 labels)
   - @ symbols (credential injection tricks)
   - Suspicious TLDs (.tk, .ml, .xyz, etc.)
   - URL shorteners (bit.ly, tinyurl, etc.)
   - Excessively long URLs
   - Hyphen-heavy domain labels
   - Brand names misplaced in subdomains
   - Suspicious path keywords (login, verify, account, etc.)
   - HTTP (non-HTTPS) protocols

4. **Redirect Chain Unrolling**
   - Follows HTTP redirects (HEAD requests, up to 10 hops)
   - Detects URL shorteners and open redirects
   - Tracks domain changes across the chain

5. **Domain Intelligence (WHOIS/RDAP)**
   - Fetches domain registration dates
   - Flags newly registered domains (<30 days old)
   - Shows registrar information and expiration dates

6. **DNS Record Analysis**
   - Verifies domain resolution (A/AAAA records)
   - Checks for valid MX (mail exchange) records
   - Flags domains with no mail configuration

7. **Third-Party Threat Intelligence**
   - Google Safe Browsing API v4
   - VirusTotal API v3
   - URLscan.io API
   - All use free tiers only

### Scoring System

- **0-100 risk score** with clear verdicts:
  - 0-14: **Safe**
  - 15-34: **Low Risk**
  - 35-59: **Moderate Risk**
  - 60-79: **High Risk**
  - 80-100: **Dangerous**

### UI/UX

- Clean, professional white & ocean-blue color palette
- Fully responsive (desktop and mobile)
- No signup required
- Simple single-page interface:
  - URL input box
  - Scan button
  - Comprehensive report with detailed findings
- Grouped findings by category
- Expandable sections for easy navigation
- Visual severity indicators

## Getting Started

### Prerequisites

- Node.js 18+ or 20+
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd phishy
```

2. Install dependencies:
```bash
npm install
```

3. Configure API keys (optional but recommended):

Copy `.env.local` and add your free API keys:

```bash
# Google Safe Browsing Lookup API v4
# https://developers.google.com/safe-browsing/v4/get-started
GOOGLE_SAFE_BROWSING_KEY=your_key_here

# VirusTotal API v3 (free tier: 4 requests/min)
# https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_key_here

# URLscan.io API (free tier: 1000 public scans/month)
# https://urlscan.io/user/profile/
URLSCAN_API_KEY=your_key_here
```

**Note**: The scanner works without API keys — it will gracefully skip threat intelligence checks and rely on the built-in detection algorithms.

4. Run the development server:
```bash
npm run dev
```

5. Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
npm run build
npm start
```

## Project Structure

```
phishy/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   └── scan/
│   │   │       └── route.ts          # API endpoint for URL scanning
│   │   ├── globals.css                # Global styles
│   │   ├── layout.tsx                 # Root layout
│   │   └── page.tsx                   # Main UI page
│   └── lib/
│       ├── detectors/
│       │   ├── homoglyph.ts           # Homoglyph & Punycode detection
│       │   ├── typosquat.ts           # Typosquatting analysis
│       │   ├── structural.ts          # Structural red flags
│       │   ├── redirect.ts            # Redirect chain unrolling
│       │   ├── dns.ts                 # DNS resolution checks
│       │   ├── domainIntel.ts         # WHOIS/RDAP lookups
│       │   └── threatIntel.ts         # Third-party API integrations
│       ├── scanner.ts                 # Main orchestration engine
│       └── types.ts                   # TypeScript type definitions
├── .env.local                         # API keys (git-ignored)
├── package.json
├── tsconfig.json
└── next.config.ts
```

## Technology Stack

- **Framework**: Next.js 15 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS 4
- **Icons**: Lucide React
- **Detection Libraries**:
  - `axios` — HTTP client for network checks
  - `dns-packet` — DNS resolution
  - `punycode` — IDN/Punycode handling
  - `levenshtein-edit-distance` — Typosquatting distance calculation
  - `whois-json` — Domain intelligence
  - `node-cache` — In-memory caching

## API Endpoints

### POST `/api/scan`

Scans a URL and returns a comprehensive analysis.

**Request Body**:
```json
{
  "url": "https://example.com"
}
```

**Response** (`ScanResult`):
```json
{
  "url": "https://example.com",
  "finalUrl": "https://example.com",
  "hostname": "example.com",
  "score": 15,
  "verdict": "Low Risk",
  "findings": [...],
  "redirectChain": [...],
  "domainIntel": {...},
  "dns": {...},
  "threatIntel": [...],
  "scannedAt": "2026-09-20T12:00:00.000Z",
  "warnings": []
}
```

## How It Works

1. **Input normalization**: Prepends `https://` if missing
2. **Static analysis**: Runs synchronous checks (homoglyphs, typosquatting, structural flags)
3. **Network analysis**: Runs parallel async checks with timeouts:
   - Redirect chain unrolling
   - DNS resolution
   - WHOIS/RDAP lookup
   - Threat intelligence APIs
4. **Score calculation**: Sums severity points from all findings (capped at 100)
5. **Verdict derivation**: Maps score to human-readable risk level
6. **Report generation**: Returns comprehensive JSON with all findings and metadata

## License

MIT License — feel free to use this in your portfolio or extend it for your own projects.

## Contributing

This is a portfolio project, but suggestions and improvements are welcome via issues or pull requests.

## Security & Privacy

- No URLs are logged or stored permanently
- All scans are ephemeral and performed on-demand
- API keys are kept server-side via environment variables
- No tracking, analytics, or telemetry

## Deployment

Deploy to Vercel, Netlify, or any Node.js hosting platform:

### Vercel (Recommended)

```bash
npm install -g vercel
vercel
```

Add your API keys as environment variables in the Vercel dashboard.

### Docker

```bash
docker build -t phishy .
docker run -p 3000:3000 phishy
```

---

**Built with Claude Code** — A professional URL security scanner ready for production deployment.
