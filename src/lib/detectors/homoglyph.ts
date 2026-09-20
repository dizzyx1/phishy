/**
 * Homoglyph & Punycode detection
 *
 * Detects Internationalized Domain Names (IDN) that use visually
 * similar characters from non-Latin scripts to impersonate known brands.
 */

import type { Finding } from "../types";

// Well-known brands whose look-alikes should be flagged
const BRAND_LIST = [
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
  "irs",
  "ebay",
  "walmart",
  "target",
];

// Common homoglyph substitution map (confusable → ASCII)
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  х: "x",
  і: "i",
  ѕ: "s",
  ѵ: "v",
  // Greek
  α: "a",
  β: "b",
  ε: "e",
  ι: "i",
  κ: "k",
  ν: "v",
  ο: "o",
  ρ: "p",
  τ: "t",
  υ: "u",
  χ: "x",
  // Latin look-alikes
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
  "ℓ": "l",
};

function normalizeHomoglyphs(text: string): string {
  return text
    .split("")
    .map((ch) => HOMOGLYPH_MAP[ch] ?? ch)
    .join("");
}

/**
 * Returns true if the hostname contains non-ASCII characters (Punycode / IDN)
 */
function isPunycode(hostname: string): boolean {
  return /[^\x00-\x7F]/.test(hostname) || hostname.includes("xn--");
}

export function detectHomoglyphs(hostname: string): Finding[] {
  const findings: Finding[] = [];
  const lower = hostname.toLowerCase();

  // 1. Punycode / IDN detection
  if (isPunycode(lower)) {
    findings.push({
      id: "homoglyph-punycode",
      label: "Punycode / IDN Domain",
      description:
        "The domain contains non-ASCII or Punycode characters (xn-- prefix). " +
        "Attackers use these to render visually identical clones of legitimate domains in the browser address bar.",
      severity: 25,
      category: "homoglyph",
    });
  }

  // 2. Homoglyph character substitution
  const normalised = normalizeHomoglyphs(lower);
  if (normalised !== lower) {
    // Check whether the normalised version resolves to a known brand
    const spoofedBrand = BRAND_LIST.find((brand) =>
      normalised.includes(brand)
    );
    if (spoofedBrand) {
      findings.push({
        id: `homoglyph-spoof-${spoofedBrand}`,
        label: `Homoglyph Impersonation: ${spoofedBrand}`,
        description:
          `The hostname "${hostname}" uses visually similar characters ` +
          `to impersonate "${spoofedBrand}". This is a classic IDN homograph phishing technique.`,
        severity: 40,
        category: "homoglyph",
      });
    } else {
      findings.push({
        id: "homoglyph-generic",
        label: "Homoglyph Characters Detected",
        description:
          "The hostname contains characters that visually resemble standard ASCII letters " +
          "from Cyrillic, Greek, or other scripts, which may be used to deceive users.",
        severity: 20,
        category: "homoglyph",
      });
    }
  }

  return findings;
}
