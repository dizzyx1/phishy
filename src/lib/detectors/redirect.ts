/**
 * Redirect chain unrolling
 *
 * Follows HTTP redirects (HEAD request, up to 10 hops) to reveal
 * the final landing page. Detects URL shorteners and open redirects.
 */

import axios from "axios";
import type { Finding, RedirectHop } from "../types";

const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 8000;

/**
 * Extracts base domain (eTLD+1 heuristic) to differentiate legitimate
 * canonicalization (e.g. google.com -> www.google.com) from malicious
 * open redirects to external domains (e.g. google.com -> evil-site.com).
 */
export function getBaseDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return hostname.toLowerCase();

  const commonMultiPartTlds = [
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gen.in",
    "com.br", "net.br", "org.br",
  ];

  const lastTwo = parts.slice(-2).join(".");
  if (commonMultiPartTlds.includes(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join(".");
  }

  return parts.slice(-2).join(".");
}

export async function unrollRedirects(
  urlString: string
): Promise<{ chain: RedirectHop[]; findings: Finding[] }> {
  const findings: Finding[] = [];
  const chain: RedirectHop[] = [];

  // Manual redirect tracking
  let currentUrl = urlString;
  let hopCount = 0;

  while (hopCount < MAX_REDIRECTS) {
    try {
      const res = await axios.head(currentUrl, {
        maxRedirects: 0,
        timeout: TIMEOUT_MS,
        validateStatus: () => true,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
      });

      chain.push({ url: currentUrl, statusCode: res.status });

      if (res.status >= 300 && res.status < 400 && res.headers.location) {
        // Redirect detected
        const nextUrl = new URL(res.headers.location, currentUrl).href;
        currentUrl = nextUrl;
        hopCount++;
      } else {
        // Final destination reached
        break;
      }
    } catch {
      // On error, record what we have and bail
      break;
    }
  }

  // Extract hostnames & base domains across the redirect chain
  const hostnames = chain.map((hop) => {
    try {
      return new URL(hop.url).hostname;
    } catch {
      return "";
    }
  }).filter(Boolean);

  const baseDomains = hostnames.map((h) => getBaseDomain(h));
  const uniqueBaseDomains = new Set(baseDomains);

  // Check if redirect is purely internal canonicalization / www addition (e.g. google.com -> www.google.com)
  const isPureCanonicalization =
    chain.length === 2 &&
    uniqueBaseDomains.size === 1 &&
    chain[0].statusCode === 301;

  // Analysis
  if (chain.length > 1 && !isPureCanonicalization) {
    findings.push({
      id: "redirect-chain",
      label: `Redirect Chain (${chain.length} hops)`,
      description:
        `The URL redirects ${chain.length} times before reaching the final destination. ` +
        "Phishing campaigns often use redirect chains to conceal the malicious landing page from scanners.",
      severity: chain.length >= 3 ? 25 : 15,
      category: "redirect",
    });
  }

  if (hopCount >= MAX_REDIRECTS) {
    findings.push({
      id: "redirect-excessive",
      label: "Excessive Redirect Loop",
      description:
        `The URL hit the maximum redirect limit (${MAX_REDIRECTS}), which may indicate ` +
        "a redirect loop or deliberate obfuscation technique.",
      severity: 30,
      category: "redirect",
    });
  }

  // Check for cross-domain changes across the chain (genuine open redirect indicator)
  if (uniqueBaseDomains.size > 1) {
    findings.push({
      id: "redirect-domain-change",
      label: "Domain Change in Redirect Chain",
      description:
        `The redirect chain crosses ${uniqueBaseDomains.size} different base domains. ` +
        "This is a hallmark of open redirects used to bypass allowlists.",
      severity: 20,
      category: "redirect",
    });
  }

  return { chain, findings };
}
