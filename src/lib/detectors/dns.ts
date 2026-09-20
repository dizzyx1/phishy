/**
 * DNS resolution checker
 *
 * Queries DNS A and MX records to verify the domain resolves and has
 * valid mail exchange configuration.
 */

import { promises as dns } from "dns";
import type { DnsInfo, Finding } from "../types";

export async function checkDns(hostname: string): Promise<{
  dns: DnsInfo | null;
  findings: Finding[];
}> {
  const findings: Finding[] = [];
  let aRecords: string[] = [];
  let mxRecords: string[] = [];
  let resolves = false;
  let hasValidMx = false;

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
