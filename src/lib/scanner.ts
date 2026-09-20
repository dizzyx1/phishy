/**
 * Phishr Core Scanner Engine
 *
 * Orchestrates all individual detection modules and aggregates findings
 * into a single unified 0-100 risk score.
 */

import { detectHomoglyphs } from "./detectors/homoglyph";
import { detectTyposquat } from "./detectors/typosquat";
import { detectStructuralFlags } from "./detectors/structural";
import { unrollRedirects } from "./detectors/redirect";
import { checkDns } from "./detectors/dns";
import { getDomainIntel } from "./detectors/domainIntel";
import { checkThreatIntel } from "./detectors/threatIntel";
import type { Finding, ScanResult, RedirectHop, ThreatIntelResult, DnsInfo, DomainIntel } from "./types";

export async function scanUrl(rawInput: string): Promise<ScanResult> {
  const warnings: string[] = [];

  // Normalize input URL (prepend https:// if missing)
  let normalizedUrl = rawInput.trim();
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = `https://${normalizedUrl}`;
  }

  let hostname = "";
  try {
    const parsed = new URL(normalizedUrl);
    hostname = parsed.hostname;
  } catch {
    // Malformed URL
    return {
      url: rawInput,
      finalUrl: null,
      hostname: "unknown",
      score: 85,
      verdict: "High Risk",
      findings: [
        {
          id: "malformed-url",
          label: "Malformed URL Structure",
          description: "The submitted URL could not be parsed as a valid web address.",
          severity: 85,
          category: "structure",
        },
      ],
      redirectChain: [],
      domainIntel: null,
      dns: null,
      threatIntel: [],
      scannedAt: new Date().toISOString(),
      warnings: ["Unable to parse URL"],
    };
  }

  // 1. Static checks (synchronous)
  const homoglyphFindings = detectHomoglyphs(hostname);
  const typosquatFindings = detectTyposquat(hostname);
  const structuralFindings = detectStructuralFlags(normalizedUrl);

  // 2. Network-based checks (run in parallel with timeouts)
  const [redirectRes, dnsRes, domainIntelRes, threatIntelRes] =
    await Promise.allSettled([
      unrollRedirects(normalizedUrl),
      checkDns(hostname),
      getDomainIntel(hostname),
      checkThreatIntel(normalizedUrl, hostname),
    ]);

  // Collect findings from network checks
  const networkFindings: Finding[] = [];
  let redirectChain: RedirectHop[] = [];
  let finalUrl: string | null = null;
  let dnsInfo: DnsInfo | null = null;
  let domainIntelInfo: DomainIntel | null = null;
  let threatIntelList: ThreatIntelResult[] = [];

  if (redirectRes.status === "fulfilled") {
    redirectChain = redirectRes.value.chain;
    networkFindings.push(...redirectRes.value.findings);
    if (redirectChain.length > 0) {
      finalUrl = redirectChain.at(-1)?.url ?? null;
    }
  } else {
    warnings.push("Redirect chain tracking timed out or failed");
  }

  if (dnsRes.status === "fulfilled") {
    dnsInfo = dnsRes.value.dns;
    networkFindings.push(...dnsRes.value.findings);
  } else {
    warnings.push("DNS resolution checks failed");
  }

  if (domainIntelRes.status === "fulfilled") {
    domainIntelInfo = domainIntelRes.value.intel;
    networkFindings.push(...domainIntelRes.value.findings);
  } else {
    warnings.push("WHOIS/RDAP domain intelligence lookup timed out");
  }

  if (threatIntelRes.status === "fulfilled") {
    threatIntelList = threatIntelRes.value;
    // Add findings for flagged third-party sources
    for (const ti of threatIntelList) {
      if (ti.flagged) {
        networkFindings.push({
          id: `threat-intel-${ti.source.toLowerCase().replace(/\s+/g, "-")}`,
          label: `Flagged by ${ti.source}`,
          description: ti.details ?? "Flagged by security vendor",
          severity: 50,
          category: "threat-intel",
        });
      }
    }
  }

  // Aggregate all findings
  const allFindings = [
    ...homoglyphFindings,
    ...typosquatFindings,
    ...structuralFindings,
    ...networkFindings,
  ];

  // Calculate 0-100 risk score
  // Sum severities, cap at 100, apply diminishing returns for multiple low-severity flags
  let rawScore = 0;
  for (const f of allFindings) {
    rawScore += f.severity;
  }

  // If any threat intel source flagged it, minimum score is 75
  const hasThreatIntelFlag = threatIntelList.some((t) => t.flagged);
  if (hasThreatIntelFlag) {
    rawScore = Math.max(rawScore, 75);
  }

  // Cap score between 0 and 100
  const finalScore = Math.min(Math.max(Math.round(rawScore), 0), 100);

  // Derive human-readable verdict
  let verdict: ScanResult["verdict"] = "Safe";
  if (finalScore >= 80) {
    verdict = "Dangerous";
  } else if (finalScore >= 60) {
    verdict = "High Risk";
  } else if (finalScore >= 35) {
    verdict = "Moderate Risk";
  } else if (finalScore >= 15) {
    verdict = "Low Risk";
  }

  return {
    url: rawInput,
    finalUrl: finalUrl ?? normalizedUrl,
    hostname,
    score: finalScore,
    verdict,
    findings: allFindings,
    redirectChain,
    domainIntel: domainIntelInfo,
    dns: dnsInfo,
    threatIntel: threatIntelList,
    scannedAt: new Date().toISOString(),
    warnings,
  };
}
