/**
 * Structural red-flag detection
 *
 * Examines the URL's anatomy for well-known phishing structural patterns
 * without any network calls.
 */

import type { Finding } from "../types";

// TLDs frequently abused in phishing campaigns
const SUSPICIOUS_TLDS = new Set([
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".xyz",
  ".pw",
  ".top",
  ".club",
  ".work",
  ".vip",
  ".online",
  ".live",
  ".site",
  ".icu",
  ".cyou",
  ".buzz",
  ".fun",
  ".link",
  ".click",
  ".download",
  ".zip",
  ".mov",
]);

// Known URL shorteners / open redirect hosts
const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "short.io",
  "is.gd",
  "su.pr",
  "bl.ink",
  "adf.ly",
  "shorte.st",
  "clickmeter.com",
  "linkbucks.com",
]);

export function detectStructuralFlags(urlString: string): Finding[] {
  const findings: Finding[] = [];

  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    findings.push({
      id: "structure-invalid-url",
      label: "Invalid or Malformed URL",
      description:
        "The submitted string could not be parsed as a valid URL, which may indicate obfuscation or a broken phishing link.",
      severity: 35,
      category: "structure",
    });
    return findings;
  }

  const { hostname, pathname, search, href, protocol } = parsed;
  const fullUrl = href;

  // 1. HTTP (no TLS)
  if (protocol === "http:") {
    findings.push({
      id: "structure-no-https",
      label: "No HTTPS / Insecure Protocol",
      description:
        "The URL uses plain HTTP instead of HTTPS. Legitimate services, especially those handling credentials, always use TLS encryption.",
      severity: 15,
      category: "structure",
    });
  }

  // 2. Raw IP address as hostname
  if (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
    hostname.startsWith("[") // IPv6
  ) {
    findings.push({
      id: "structure-raw-ip",
      label: "Raw IP Address in Hostname",
      description:
        `The URL uses a bare IP address (${hostname}) instead of a domain name. ` +
        "Phishing pages are often hosted on transient IP addresses to bypass domain blacklists.",
      severity: 30,
      category: "structure",
    });
  }

  // 3. Excessive subdomains (>= 4 labels)
  const labels = hostname.split(".");
  if (labels.length >= 4) {
    findings.push({
      id: "structure-excessive-subdomains",
      label: "Excessive Subdomain Depth",
      description:
        `The hostname has ${labels.length} labels (e.g. "a.b.c.evil.com"). ` +
        "Phishers often prepend brand names as subdomains: paypal.account.login.evil.com.",
      severity: 20,
      category: "structure",
    });
  }

  // 4. @ symbol in URL (credential injection / redirect trick)
  if (fullUrl.includes("@")) {
    findings.push({
      id: "structure-at-symbol",
      label: "@ Symbol in URL",
      description:
        "The URL contains an @ symbol. Browsers treat everything before @ as " +
        "user credentials, so https://google.com@evil.com actually navigates to evil.com.",
      severity: 40,
      category: "structure",
    });
  }

  // 5. Suspicious TLD
  const tld = "." + labels.at(-1)?.toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push({
      id: `structure-suspicious-tld-${tld}`,
      label: `Suspicious TLD: ${tld}`,
      description:
        `The domain ends with "${tld}", a top-level domain that is disproportionately ` +
        "used in phishing campaigns due to free or anonymous registration.",
      severity: 15,
      category: "structure",
    });
  }

  // 6. Known URL shortener
  const bare = hostname.replace(/^www\./, "");
  if (URL_SHORTENERS.has(bare)) {
    findings.push({
      id: "structure-url-shortener",
      label: "URL Shortener Detected",
      description:
        `The host "${hostname}" is a known URL shortener. Shortened URLs conceal the ` +
        "real destination and are commonly used to bypass phishing filters.",
      severity: 20,
      category: "structure",
    });
  }

  // 7. Excessively long URL (> 100 chars total)
  if (fullUrl.length > 100) {
    findings.push({
      id: "structure-long-url",
      label: "Excessively Long URL",
      description:
        `The URL is ${fullUrl.length} characters long. Very long URLs often embed ` +
        "encoded payloads or use query-string obfuscation to confuse URL scanners.",
      severity: 10,
      category: "structure",
    });
  }

  // 8. Multiple dashes in SLD
  const sld = labels.at(-2) ?? "";
  if ((sld.match(/-/g) ?? []).length >= 2) {
    findings.push({
      id: "structure-hyphen-heavy-sld",
      label: "Hyphen-Heavy Domain Label",
      description:
        `The second-level domain "${sld}" contains multiple hyphens, ` +
        'a pattern commonly used in phishing domains like "paypal-secure-login.com".',
      severity: 15,
      category: "structure",
    });
  }

  // 9. Brand name in subdomain but not in SLD
  const brandsMisplaced = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "netflix",
    "instagram",
    "twitter",
    "bankofamerica",
    "chase",
    "wellsfargo",
  ];
  const subdomains = labels.slice(0, -2).join(".");
  for (const brand of brandsMisplaced) {
    if (subdomains.includes(brand) && !sld.includes(brand)) {
      findings.push({
        id: `structure-brand-in-subdomain-${brand}`,
        label: `Brand Name in Subdomain: "${brand}"`,
        description:
          `"${brand}" appears in a subdomain rather than the actual domain name. ` +
          `This is a classic phishing tactic that makes the URL look like an official ` +
          `${brand} page while the real domain is "${sld}.${labels.at(-1)}".`,
        severity: 35,
        category: "structure",
      });
      break;
    }
  }

  // 10. Suspicious path keywords
  const pathLower = (pathname + search).toLowerCase();
  const suspiciousPathWords = [
    "login",
    "signin",
    "secure",
    "verify",
    "account",
    "update",
    "confirm",
    "banking",
    "webscr",
    "cmd",
    "paypal",
    "password",
  ];
  const matchedPathWords = suspiciousPathWords.filter((w) =>
    pathLower.includes(w)
  );
  if (matchedPathWords.length >= 2) {
    findings.push({
      id: "structure-suspicious-path",
      label: "Suspicious Path Keywords",
      description:
        `The URL path contains ${matchedPathWords.length} suspicious keywords ` +
        `(${matchedPathWords.join(", ")}). Phishing pages commonly include these to appear ` +
        "legitimate while prompting users to enter credentials.",
      severity: 15,
      category: "structure",
    });
  }

  return findings;
}
