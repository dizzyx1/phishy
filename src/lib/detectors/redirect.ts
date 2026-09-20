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

  // Analysis
  if (chain.length > 1) {
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

  // Check for domain changes across the chain (open redirect indicator)
  const domains = chain.map((hop) => {
    try {
      return new URL(hop.url).hostname;
    } catch {
      return "";
    }
  });
  const uniqueDomains = new Set(domains.filter(Boolean));
  if (uniqueDomains.size > 1) {
    findings.push({
      id: "redirect-domain-change",
      label: "Domain Change in Redirect Chain",
      description:
        `The redirect chain crosses ${uniqueDomains.size} different domains. ` +
        "This is a hallmark of open redirects used to bypass allowlists.",
      severity: 20,
      category: "redirect",
    });
  }

  return { chain, findings };
}
