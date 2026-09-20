/**
 * Domain intelligence via WHOIS / RDAP
 *
 * Fetches domain registration data to determine domain age.
 * Newly registered domains (< 30 days) are flagged as high-risk.
 */

import type { DomainIntel, Finding } from "../types";

const YOUNG_DOMAIN_THRESHOLD_DAYS = 30;

export async function getDomainIntel(hostname: string): Promise<{
  intel: DomainIntel | null;
  findings: Finding[];
}> {
  const findings: Finding[] = [];
  let intel: DomainIntel | null = null;

  try {
    // Dynamic import to prevent bundler / serverless crash if whois-json or raw socket fails
    const whoisModule = await import("whois-json").catch(() => null);
    const lookupAsync = whoisModule?.lookupAsync || whoisModule?.default?.lookupAsync;

    if (!lookupAsync) {
      return { intel: null, findings: [] };
    }

    const whoisData = await Promise.race([
      lookupAsync(hostname, { timeout: 5000 }),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
    ]).catch(() => null);

    if (!whoisData) {
      return { intel: null, findings: [] };
    }

    const creationDate = extractDate(
      whoisData.creationDate || whoisData.created || whoisData.registrationDate
    );
    const expirationDate = extractDate(
      whoisData.expirationDate || whoisData.expires
    );
    const registrar =
      (whoisData.registrar as string) ||
      (whoisData.registrarName as string) ||
      null;

    const domainAgeDays = creationDate
      ? Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24))
      : null;

    intel = {
      registrar,
      creationDate: creationDate?.toISOString() ?? null,
      expirationDate: expirationDate?.toISOString() ?? null,
      domainAgeDays,
    };

    // Flag young domains
    if (domainAgeDays !== null && domainAgeDays < YOUNG_DOMAIN_THRESHOLD_DAYS) {
      findings.push({
        id: "domain-young",
        label: `Domain Recently Registered (${domainAgeDays} days old)`,
        description:
          `The domain was registered only ${domainAgeDays} days ago. ` +
          "Phishing domains are typically short-lived and registered shortly before a campaign.",
        severity: domainAgeDays < 14 ? 35 : 25,
        category: "domain-intel",
      });
    }
  } catch (err) {
    // WHOIS lookup failed or timed out — not necessarily malicious
    return { intel: null, findings: [] };
  }

  return { intel, findings };
}

function extractDate(raw: unknown): Date | null {
  if (!raw) return null;
  if (raw instanceof Date) return raw;
  if (typeof raw === "string") {
    const parsed = new Date(raw);
    return isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
}
