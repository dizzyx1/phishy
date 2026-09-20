/**
 * Domain intelligence via RDAP (Registration Data Access Protocol)
 *
 * Fetches domain registration data over HTTPS (RDAP REST API).
 * Unlike legacy port 43 WHOIS sockets, RDAP runs seamlessly in
 * serverless edge/lambda environments like Vercel.
 *
 * Newly registered domains (< 30 days) are flagged as high-risk.
 */

import axios from "axios";
import type { DomainIntel, Finding } from "../types";

const YOUNG_DOMAIN_THRESHOLD_DAYS = 30;

export async function getDomainIntel(hostname: string): Promise<{
  intel: DomainIntel | null;
  findings: Finding[];
}> {
  const findings: Finding[] = [];
  let intel: DomainIntel | null = null;

  try {
    // Extract base domain if hostname has subdomains (e.g. sub.example.com -> example.com)
    const domainParts = hostname.toLowerCase().split(".").filter(Boolean);
    let queryDomain = hostname;
    if (domainParts.length > 2) {
      queryDomain = domainParts.slice(-2).join(".");
    }

    const res = await axios.get(`https://rdap.org/domain/${encodeURIComponent(queryDomain)}`, {
      headers: { Accept: "application/rdap+json, application/json" },
      timeout: 5000,
      validateStatus: (status) => status < 500,
    });

    if (res.status === 200 && res.data) {
      const data = res.data;

      // Extract events (registration, expiration, last changed)
      const events = Array.isArray(data.events) ? data.events : [];
      const regEvent = events.find(
        (e: { eventAction?: string }) =>
          e.eventAction === "registration" || e.eventAction === "registered"
      );
      const expEvent = events.find(
        (e: { eventAction?: string }) =>
          e.eventAction === "expiration" || e.eventAction === "expired"
      );

      const creationDate = extractDate(regEvent?.eventDate);
      const expirationDate = extractDate(expEvent?.eventDate);

      // Extract registrar name from entities
      let registrar: string | null = null;
      if (Array.isArray(data.entities)) {
        const registrarEntity = data.entities.find((ent: { roles?: string[] }) =>
          ent.roles?.includes("registrar")
        );
        if (registrarEntity) {
          const fnEntry = registrarEntity.vcardArray?.[1]?.find(
            (item: unknown[]) => Array.isArray(item) && item[0] === "fn"
          );
          registrar = (fnEntry?.[3] as string) || registrarEntity.handle || null;
        }
      }

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
    }
  } catch {
    // RDAP lookup failed or timed out — not necessarily malicious
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
