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
import { checkSslAndHeaders } from "./detectors/sslHeaders";
import { getSiteOverview } from "./detectors/siteOverview";
import { normalizeUrl, parseAndValidateUrl } from "./urlNormalizer";
import type { Finding, ScanResult, RedirectHop, ThreatIntelResult, DnsInfo, DomainIntel, SslHeadersInfo, SiteOverview } from "./types";

export async function scanUrl(rawInput: string): Promise<ScanResult> {
  const warnings: string[] = [];

  let normalizedUrl = "";
  let hostname = "";
  try {
    normalizedUrl = normalizeUrl(rawInput);
    const parsed = parseAndValidateUrl(normalizedUrl);
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
      sslInfo: null,
      siteOverview: null,
      scannedAt: new Date().toISOString(),
      warnings: ["Unable to parse URL"],
    };
  }

  // 1. Static checks (synchronous)
  const homoglyphFindings = detectHomoglyphs(hostname);
  const typosquatFindings = detectTyposquat(hostname);
  const structuralFindings = detectStructuralFlags(normalizedUrl);

  // 2. Network-based checks (run in parallel with timeouts)
  const [redirectRes, dnsRes, domainIntelRes, threatIntelRes, sslRes, overviewRes] =
    await Promise.allSettled([
      unrollRedirects(normalizedUrl),
      checkDns(hostname),
      getDomainIntel(hostname),
      checkThreatIntel(normalizedUrl, hostname),
      checkSslAndHeaders(normalizedUrl),
      getSiteOverview(normalizedUrl, hostname)
    ]);

  // Collect findings from network checks
  const networkFindings: Finding[] = [];
  let redirectChain: RedirectHop[] = [];
  let finalUrl: string | null = null;
  let dnsInfo: DnsInfo | null = null;
  let domainIntelInfo: DomainIntel | null = null;
  let threatIntelList: ThreatIntelResult[] = [];
  let sslInfo: SslHeadersInfo | null = null;
  let siteOverview: SiteOverview | null = null;

  if (redirectRes.status === "fulfilled") {
    redirectChain = redirectRes.value.chain;
    networkFindings.push(...redirectRes.value.findings);
    if (redirectChain.length > 0) {
      finalUrl = redirectChain.at(-1)?.url ?? null;
      // If we got redirected, the SSL & overview might be better verified against the final URL
      // (For this implementation, we rely on the initial checks that follow redirects internally)
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

  if (sslRes.status === "fulfilled") {
    sslInfo = sslRes.value.sslInfo;
    networkFindings.push(...sslRes.value.findings);
  } else {
    warnings.push("SSL & Security Headers check timed out or failed");
  }

  if (overviewRes.status === "fulfilled") {
    siteOverview = overviewRes.value;
  } else {
    warnings.push("Site Overview (web search/metadata) extraction failed");
  }

  // Aggregate all findings
  const allFindings = [
    ...homoglyphFindings,
    ...typosquatFindings,
    ...structuralFindings,
    ...networkFindings,
  ];

  // Calculate 0-100 risk score
  let rawScore = 0;
  for (const f of allFindings) {
    rawScore += f.severity;
  }

  const hasThreatIntelFlag = threatIntelList.some((t) => t.flagged);
  if (hasThreatIntelFlag) {
    rawScore = Math.max(rawScore, 50);
  }

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
    sslInfo,
    siteOverview,
    scannedAt: new Date().toISOString(),
    warnings,
  };
}
