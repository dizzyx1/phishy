/**
 * Typosquatting detection via Levenshtein distance
 *
 * Compares the input hostname against a curated list of popular domains.
 * If the edit-distance is ≤ 2 (and the hostname is NOT the brand itself)
 * we flag it as a likely typosquat.
 */

import { levenshteinEditDistance as levenshtein } from "levenshtein-edit-distance";
import type { Finding } from "../types";

// Top brands to compare against (SLD only, no TLD)
const POPULAR_DOMAINS = [
  "google",
  "facebook",
  "microsoft",
  "apple",
  "amazon",
  "paypal",
  "netflix",
  "instagram",
  "twitter",
  "youtube",
  "gmail",
  "outlook",
  "linkedin",
  "dropbox",
  "github",
  "bankofamerica",
  "chase",
  "wellsfargo",
  "citibank",
  "ebay",
  "walmart",
  "target",
  "airbnb",
  "slack",
  "zoom",
  "spotify",
  "pinterest",
  "snapchat",
  "tiktok",
  "reddit",
  "tumblr",
  "wordpress",
  "shopify",
  "stripe",
  "coinbase",
  "binance",
  "kraken",
  "robinhood",
  "fedex",
  "ups",
  "usps",
  "dhl",
  "steam",
  "epicgames",
  "roblox",
  "twitch",
  "discord",
];

/** Extract second-level domain label (e.g. "paypa1" from "paypa1.com") */
function extractSld(hostname: string): string {
  // Remove trailing dots, strip www.
  const cleaned = hostname.replace(/\.$/, "").replace(/^www\./, "");
  const parts = cleaned.split(".");
  // Return the part before the last TLD segment(s)
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

export function detectTyposquat(hostname: string): Finding[] {
  const findings: Finding[] = [];
  const sld = extractSld(hostname.toLowerCase());

  for (const brand of POPULAR_DOMAINS) {
    // Exact match → user is legitimately on the brand's domain
    if (sld === brand) break;

    const dist = levenshtein(sld, brand);
    if (dist > 0 && dist <= 2) {
      findings.push({
        id: `typosquat-${brand}`,
        label: `Typosquat: "${sld}" ≈ "${brand}"`,
        description:
          `The domain label "${sld}" has an edit distance of ${dist} from "${brand}", ` +
          `which is a classic typosquatting pattern designed to catch users who mistype the real URL.`,
        severity: dist === 1 ? 30 : 20,
        category: "typosquat",
      });
      // Only flag the closest match to avoid spam
      break;
    }
  }

  return findings;
}
