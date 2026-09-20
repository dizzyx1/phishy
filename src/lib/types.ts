/** Shared types for Phishr analysis engine */

export interface Finding {
  /** Machine-readable ID, e.g. "homoglyph-cyrillic" */
  id: string;
  /** Human label */
  label: string;
  /** Explanation shown in the report */
  description: string;
  /** Points added to the risk score (0-100 scale) */
  severity: number;
  /** Grouping for the report UI */
  category: FindingCategory;
}

export type FindingCategory =
  | "homoglyph"
  | "typosquat"
  | "structure"
  | "redirect"
  | "domain-intel"
  | "dns"
  | "threat-intel";

export interface RedirectHop {
  url: string;
  statusCode: number;
}

export interface DomainIntel {
  registrar: string | null;
  creationDate: string | null;
  expirationDate: string | null;
  domainAgeDays: number | null;
}

export interface DnsInfo {
  aRecords: string[];
  mxRecords: string[];
  hasValidMx: boolean;
  resolves: boolean;
}

export interface ThreatIntelResult {
  source: string;
  flagged: boolean;
  details: string | null;
}

export interface ScanResult {
  /** Original URL submitted */
  url: string;
  /** Final landing URL after redirects */
  finalUrl: string | null;
  /** Hostname extracted from the URL */
  hostname: string;
  /** Overall risk score 0 (safe) – 100 (malicious) */
  score: number;
  /** Risk label derived from the score */
  verdict: "Safe" | "Low Risk" | "Moderate Risk" | "High Risk" | "Dangerous";
  /** Individual findings that contributed to the score */
  findings: Finding[];
  /** Redirect chain if applicable */
  redirectChain: RedirectHop[];
  /** WHOIS / RDAP domain intelligence */
  domainIntel: DomainIntel | null;
  /** DNS resolution data */
  dns: DnsInfo | null;
  /** Third-party threat intel results */
  threatIntel: ThreatIntelResult[];
  /** ISO timestamp of when the scan was performed */
  scannedAt: string;
  /** Whether external checks timed out or failed */
  warnings: string[];
}
