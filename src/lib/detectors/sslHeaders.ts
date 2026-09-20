/**
 * SSL & Target Site Security Headers Analyzer
 *
 * Inspects whether the target URL supports HTTPS and implements
 * essential security headers (HSTS, CSP, X-Frame-Options).
 */

import axios from "axios";
import type { Finding } from "../types";

export interface SslHeadersInfo {
  isHttps: boolean;
  hasHsts: boolean;
  hasCsp: boolean;
  hasXFrameOptions: boolean;
  hasXContentTypeOptions: boolean;
  serverHeader: string | null;
}

export async function checkSslAndHeaders(urlString: string): Promise<{
  sslInfo: SslHeadersInfo | null;
  findings: Finding[];
}> {
  const findings: Finding[] = [];
  const parsed = new URL(urlString);
  const isHttps = parsed.protocol === "https:";

  let hasHsts = false;
  let hasCsp = false;
  let hasXFrameOptions = false;
  let hasXContentTypeOptions = false;
  let serverHeader: string | null = null;

  try {
    const res = await axios.get(urlString, {
      timeout: 6000,
      maxRedirects: 3,
      validateStatus: () => true,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      },
    });

    const headers = res.headers;

    hasHsts = Boolean(headers["strict-transport-security"]);
    hasCsp = Boolean(headers["content-security-policy"]);
    hasXFrameOptions = Boolean(headers["x-frame-options"]);
    hasXContentTypeOptions = Boolean(headers["x-content-type-options"]);
    serverHeader = (headers["server"] as string) || null;

    if (!isHttps) {
      findings.push({
        id: "ssl-no-https",
        label: "Insecure Connection (HTTP)",
        description:
          "The target site does not use HTTPS by default. Traffic is transmitted in plain text, making it vulnerable to interception and tampering.",
        severity: 20,
        category: "ssl",
      });
    }

    if (isHttps && !hasHsts) {
      findings.push({
        id: "ssl-no-hsts",
        label: "Missing HSTS Header",
        description:
          "The domain does not enforce HTTP Strict Transport Security (HSTS), leaving users susceptible to SSL-stripping attacks.",
        severity: 5,
        category: "ssl",
      });
    }

    if (!hasCsp) {
      findings.push({
        id: "headers-missing-csp",
        label: "Missing Content Security Policy (CSP)",
        description:
          "The site lacks a Content Security Policy, increasing exposure to Cross-Site Scripting (XSS) and data injection.",
        severity: 5,
        category: "ssl",
      });
    }

    if (!hasXFrameOptions && !hasCsp) {
      findings.push({
        id: "headers-missing-xframe",
        label: "Missing Clickjacking Protection",
        description:
          "Neither X-Frame-Options nor frame-ancestors CSP directive is configured, leaving the site open to clickjacking iframe embedding.",
        severity: 5,
        category: "ssl",
      });
    }

    return {
      sslInfo: {
        isHttps,
        hasHsts,
        hasCsp,
        hasXFrameOptions,
        hasXContentTypeOptions,
        serverHeader,
      },
      findings,
    };
  } catch {
    // If the request fails completely (e.g. invalid SSL certificate or host down)
    if (isHttps) {
      findings.push({
        id: "ssl-invalid-cert",
        label: "SSL/TLS Connection Issue",
        description:
          "Failed to establish a secure SSL/TLS connection. The certificate may be invalid, expired, self-signed, or unreachable.",
        severity: 35,
        category: "ssl",
      });
    }

    return {
      sslInfo: {
        isHttps,
        hasHsts: false,
        hasCsp: false,
        hasXFrameOptions: false,
        hasXContentTypeOptions: false,
        serverHeader: null,
      },
      findings,
    };
  }
}
