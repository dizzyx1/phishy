/**
 * Third-party threat intelligence integrations
 *
 * Checks Google Safe Browsing, VirusTotal, and URLscan.io (all free tiers).
 * Gracefully skips any provider whose API key is not configured.
 */

import axios from "axios";
import type { ThreatIntelResult } from "../types";

export async function checkThreatIntel(
  targetUrl: string,
  hostname: string
): Promise<ThreatIntelResult[]> {
  const results: ThreatIntelResult[] = [];

  // Run all enabled providers in parallel
  const checks: Promise<void>[] = [];

  // 1. Google Safe Browsing Lookup API v4
  if (process.env.GOOGLE_SAFE_BROWSING_KEY) {
    checks.push(
      (async () => {
        try {
          const res = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
            {
              client: { clientId: "phishr-scanner", clientVersion: "1.0.0" },
              threatInfo: {
                threatTypes: [
                  "MALWARE",
                  "SOCIAL_ENGINEERING",
                  "UNWANTED_SOFTWARE",
                  "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: targetUrl }],
              },
            },
            { timeout: 5000 }
          );

          const matches = res.data?.matches;
          results.push({
            source: "Google Safe Browsing",
            flagged: Boolean(matches && matches.length > 0),
            details: matches
              ? matches.map((m: { threatType: string }) => m.threatType).join(", ")
              : "No threats detected",
          });
        } catch {
          results.push({
            source: "Google Safe Browsing",
            flagged: false,
            details: "Service unavailable or rate limited",
          });
        }
      })()
    );
  }

  // 2. VirusTotal API v3
  if (process.env.VIRUSTOTAL_API_KEY) {
    checks.push(
      (async () => {
        try {
          // VirusTotal requires base64url-encoded URL without padding
          const urlId = Buffer.from(targetUrl)
            .toString("base64url");
          const res = await axios.get(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            {
              headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
              timeout: 5000,
            }
          );

          const stats = res.data?.data?.attributes?.last_analysis_stats as Record<string, number> | undefined;
          const malicious = stats?.malicious ?? 0;
          const suspicious = stats?.suspicious ?? 0;
          const totalVendors = Object.values(stats ?? {}).reduce((a, b) => a + b, 0);

          // Industry standard: Require at least 2 malicious or 3 suspicious/malicious vendors to reach consensus
          // This eliminates single-engine heuristic noise on high-traffic domains like google.com
          const isFlagged = malicious >= 2 || (malicious + suspicious) >= 3;

          let detailsMsg = "No threats detected";
          if (stats && totalVendors > 0) {
            if (isFlagged) {
              detailsMsg = `${malicious + suspicious} / ${totalVendors} security vendors flagged this URL as malicious`;
            } else if (malicious + suspicious > 0) {
              detailsMsg = `${malicious + suspicious} / ${totalVendors} vendors flagged (below consensus threshold — engine noise)`;
            } else {
              detailsMsg = `0 / ${totalVendors} vendors detected threats (Clean)`;
            }
          }

          results.push({
            source: "VirusTotal",
            flagged: isFlagged,
            details: detailsMsg,
          });
        } catch {
          results.push({
            source: "VirusTotal",
            flagged: false,
            details: "Service unavailable or URL not found in database",
          });
        }
      })()
    );
  }

  // 3. URLscan.io API
  if (process.env.URLSCAN_API_KEY) {
    checks.push(
      (async () => {
        try {
          // URLscan requires URL search
          const res = await axios.get(
            `https://urlscan.io/api/v1/search/?q=page.url:"${targetUrl}"`,
            {
              headers: { "API-Key": process.env.URLSCAN_API_KEY },
              timeout: 5000,
            }
          );

          const hits = res.data?.results ?? [];
          const maliciousHits = hits.filter(
            (h: { verdicts?: { overall?: { malicious?: boolean } } }) => h.verdicts?.overall?.malicious
          );

          results.push({
            source: "URLscan.io",
            flagged: maliciousHits.length > 0,
            details:
              hits.length > 0
                ? `${maliciousHits.length} malicious verdicts across ${hits.length} historical scans`
                : "No historical scans found",
          });
        } catch {
          results.push({
            source: "URLscan.io",
            flagged: false,
            details: "Service unavailable or rate limited",
          });
        }
      })()
    );
  }

  await Promise.allSettled(checks);
  return results;
}
