# Phishy - Portfolio Summary

## Project Overview

**Phishy** is a production-ready web application that detects phishing attempts and malicious URLs through comprehensive static and network-based analysis. Built as a portfolio project demonstrating full-stack development, cybersecurity knowledge, and professional UI/UX design.

**Live Demo**: Run locally with `npm run dev` at http://localhost:3000

## Key Features Implemented

### 1. Multi-Layer Detection Engine
- **Homoglyph & Punycode Detection**: Identifies Unicode character substitution attacks
- **Typosquatting Analysis**: Levenshtein distance calculation against 40+ popular brands
- **Structural Analysis**: 10+ red flag patterns (raw IPs, @ symbols, suspicious TLDs, etc.)
- **Redirect Chain Unrolling**: Follows HTTP redirects to reveal hidden destinations
- **Domain Intelligence**: WHOIS/RDAP lookups for domain age and registration data
- **DNS Verification**: A/AAAA and MX record validation
- **Threat Intelligence**: Integration with Google Safe Browsing, VirusTotal, and URLscan.io (free tiers)

### 2. Scoring System
- 0-100 risk score with clear verdicts (Safe, Low Risk, Moderate Risk, High Risk, Dangerous)
- Severity-based aggregation from all detection modules
- Minimum score thresholds when flagged by threat intelligence APIs

### 3. Professional UI/UX
- Clean white & ocean-blue color palette
- Fully responsive design (mobile + desktop)
- No authentication required - instant scanning
- Grouped, expandable findings by category
- Visual severity indicators and detailed explanations

## Technical Stack

- **Framework**: Next.js 15 with App Router
- **Language**: TypeScript (strict mode)
- **Styling**: Tailwind CSS 4
- **Icons**: Lucide React
- **Detection Libraries**: axios, dns, whois-json, levenshtein-edit-distance, punycode

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Frontend (React)                    │
│  - URL input → Scan button → Report display             │
└────────────────────┬────────────────────────────────────┘
                     │
                     ↓ POST /api/scan
┌─────────────────────────────────────────────────────────┐
│                  Scanner Engine (Node.js)                │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Static Checks (Synchronous)                    │   │
│  │  - Homoglyph detection                          │   │
│  │  - Typosquatting comparison                     │   │
│  │  - Structural red flags                         │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Network Checks (Parallel, with timeouts)      │   │
│  │  - Redirect chain unrolling                     │   │
│  │  - DNS resolution                               │   │
│  │  - WHOIS/RDAP lookup                            │   │
│  │  - Threat intel APIs (3 providers)              │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Aggregation & Scoring                          │   │
│  │  - Sum severity points (cap at 100)             │   │
│  │  - Derive verdict                               │   │
│  │  - Return comprehensive JSON report             │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Test Results

### Malicious URL Test
**Input**: `http://paypa1.secure-login.account.verify.xyz`

**Result**: 
- Score: **100/100** (Dangerous)
- Findings: 5 critical issues detected
  - Homoglyph impersonation of PayPal
  - No HTTPS encryption
  - Excessive subdomain depth (5 labels)
  - Suspicious .xyz TLD
  - Domain does not resolve

### Legitimate URL Test
**Input**: `https://github.com`

**Result**:
- Score: **0/100** (Safe)
- Findings: None
- DNS: Resolves with valid MX records

## Project Structure

```
phishy/
├── src/
│   ├── app/
│   │   ├── api/scan/route.ts    # API endpoint
│   │   ├── layout.tsx            # Root layout
│   │   ├── page.tsx              # Main UI
│   │   └── globals.css           # Global styles
│   ├── lib/
│   │   ├── detectors/            # Individual detection modules
│   │   │   ├── homoglyph.ts
│   │   │   ├── typosquat.ts
│   │   │   ├── structural.ts
│   │   │   ├── redirect.ts
│   │   │   ├── dns.ts
│   │   │   ├── domainIntel.ts
│   │   │   └── threatIntel.ts
│   │   ├── scanner.ts            # Main orchestration engine
│   │   └── types.ts              # TypeScript definitions
│   └── types/
│       └── whois-json.d.ts       # Type declarations
├── .env.local                    # API keys (git-ignored)
├── package.json
└── README.md
```

## Deployment Options

1. **Vercel** (Recommended - one-click deploy)
2. **Netlify**
3. **Any Node.js hosting platform**
4. **Docker** (Dockerfile ready)

## API Keys Configuration

The app works without API keys using built-in detection algorithms. For full threat intelligence:

- Google Safe Browsing API (free)
- VirusTotal API (free tier: 4 requests/min)
- URLscan.io API (free tier: 1000 scans/month)

## Portfolio Highlights

✅ **Full-stack development**: Next.js 15, TypeScript, React 19, Tailwind CSS 4  
✅ **Security domain expertise**: Deep understanding of phishing attack vectors  
✅ **API integration**: Multiple third-party threat intelligence services  
✅ **Professional UI/UX**: Responsive, accessible, production-ready design  
✅ **Code quality**: Type-safe, modular architecture, comprehensive error handling  
✅ **Ready for production**: Built to scale, deployable immediately  

## Build & Run

```bash
# Install dependencies
npm install

# Development server
npm run dev

# Production build
npm run build
npm start
```

## Git Repository Status

✅ Initial commit created with all source files  
✅ Comprehensive README.md included  
✅ .gitignore configured  
✅ Clean commit history ready for portfolio  

---

**Built with**: Next.js 15, TypeScript, Tailwind CSS, React 19  
**Development time**: Single session (fully functional from scratch)  
**Status**: Production-ready
