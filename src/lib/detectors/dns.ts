/**
 * DNS resolution checker
 *
 * Queries DNS A and MX records to verify the domain resolves and has
 * valid mail exchange configuration.
 *
 * Note: Node.js dns module may not work in serverless environments like Vercel.
 * This function gracefully degrades when dns is unavailable.
 */

import type { DnsInfo, Finding } from "../types";

// Dynamically import dns only if available (won't work in Vercel edge/serverless)
let dns: typeof import("dns").promises | null = null;
try {
  // @ts-ignore - dynamic import
  dns = require("dns").promises;
} catch {
  // DNS module not available in this environment
}

export async function checkDns(hostname: string): Promise<{
  dns: DnsInfo | null;
  findings: Finding[];
}> {
  const findings: Finding[] = [];
  let aRecords: string[] = [];
  let mxRecords: string[] = [];
  let resolves = false;
  let hasValidMx = false;

  // Skip DNS checks if module is unavailable (serverless environment)
  if (!dns) {
    return {
      dns: null,
      findings: [],
    };
  }

  try {
    // A records (IPv4)
    const aResult = await dns.resolve4(hostname).catch(() => []);
    aRecords = aResult;
    if (aRecords.length > 0) {
      resolves = true;
    }
  } catch {
    // Falls through to check MX
  }

  try {
    // MX records (mail exchange)
    const mxResult = await dns.resolveMx(hostname).catch(() => []);
    mxRecords = mxResult.map((r) => r.exchange);
    hasValidMx = mxRecords.length > 0;
  } catch {
    // No MX records
  }

  // Try AAAA if no A records
  if (!resolves) {
    try {
      const aaaaResult = await dns.resolve6(hostname).catch(() => []);
      if (aaaaResult.length > 0) {
        resolves = true;
        aRecords.push(...aaaaResult);
      }
    } catch {
      // Does not resolve at all
    }
  }

  if (!resolves) {
    findings.push({
      id: "dns-no-resolution",
      label: "Domain Does Not Resolve",
      description:
        `The domain "${hostname}" does not resolve to any IP address. ` +
        "This may indicate a freshly registered domain that has not been configured yet, or a typo.",
      severity: 30,
      category: "dns",
    });
  }

  if (resolves && !hasValidMx) {
    findings.push({
      id: "dns-no-mx",
      label: "No Mail Exchange (MX) Records",
      description:
        "The domain has no MX records configured. Legitimate business domains typically have mail servers set up. " +
        "Phishing domains often skip this to reduce traceability.",
      severity: 15,
      category: "dns",
    });
  }

  return {
    dns: {
      aRecords,
      mxRecords,
      hasValidMx,
      resolves,
    },
    findings,
  };
}
