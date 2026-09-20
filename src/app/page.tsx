"use client";

import { useState, useRef, useEffect } from "react";
import {
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Globe,
  Server,
  Mail,
  History,
  FileWarning,
  Link,
} from "lucide-react";
import type {
  ScanResult,
  Finding,
  FindingCategory,
  RedirectHop,
} from "@/lib/types";

export default function Home() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  async function handleScan() {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) return;

    setScanning(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmedUrl }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? "Scan failed");
      }

      const data: ScanResult = await res.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
    } finally {
      setScanning(false);
    }
  }

  useEffect(() => {
    if (result && resultRef.current) {
      resultRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [result]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !scanning) {
      handleScan();
    }
  }

  return (
    <div className="flex flex-col min-h-screen">
      {/* Header */}
      <header className="border-b border-[var(--gray-100)] bg-white">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center gap-3">
          <Shield className="w-7 h-7 text-[var(--ocean-600)]" strokeWidth={2} />
          <h1 className="text-xl font-semibold text-[var(--gray-900)] tracking-tight">
            Phishr
          </h1>
        </div>
      </header>

      {/* Hero & Scanner */}
      <main className="flex-1 flex flex-col">
        <section className="bg-[var(--ocean-50)] border-b border-[var(--ocean-100)]">
          <div className="max-w-4xl mx-auto px-4 py-12 md:py-16 text-center">
            <h2 className="text-2xl md:text-3xl font-semibold text-[var(--gray-900)] mb-3">
              Scan any URL for phishing threats
            </h2>
            <p className="text-[var(--gray-500)] text-sm md:text-base max-w-xl mx-auto mb-8">
              Detect homoglyphs, typosquatting, malicious redirects, suspicious
              domains, and more — in seconds.
            </p>

            {/* Scanner Input */}
            <div className="max-w-2xl mx-auto flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-5 h-5 text-[var(--gray-400)]" />
                <input
                  type="text"
                  placeholder="Enter a URL to scan..."
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={scanning}
                  className="w-full h-12 pl-11 pr-4 rounded-lg border border-[var(--gray-200)] bg-white text-[var(--gray-900)] placeholder:text-[var(--gray-400)] text-sm focus:outline-none focus:ring-2 focus:ring-[var(--ocean-300)] focus:border-[var(--ocean-400)] transition disabled:opacity-60 shadow-sm"
                />
              </div>
              <button
                onClick={handleScan}
                disabled={scanning || !url.trim()}
                className="h-12 px-6 rounded-lg bg-[var(--ocean-600)] text-white font-medium text-sm hover:bg-[var(--ocean-700)] active:bg-[var(--ocean-800)] disabled:opacity-50 disabled:cursor-not-allowed transition shadow-sm flex items-center justify-center gap-2 cursor-pointer"
              >
                {scanning ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Shield className="w-4 h-4" />
                )}
                {scanning ? "Scanning..." : "Scan URL"}
              </button>
            </div>

            {error && (
              <p className="mt-4 text-sm text-[var(--danger)]">{error}</p>
            )}
          </div>
        </section>

        {/* Results */}
        {result && (
          <section ref={resultRef} className="py-8 md:py-12">
            <div className="max-w-4xl mx-auto px-4">
              <Report result={result} />
            </div>
          </section>
        )}

        {/* Features when no results */}
        {!result && !scanning && (
          <section className="py-12 md:py-16">
            <div className="max-w-4xl mx-auto px-4">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
                <FeatureCard
                  icon={<FileWarning className="w-5 h-5" />}
                  title="Homoglyph Detection"
                  desc="Spotting lookalike Unicode characters used to forge legitimate-looking domains"
                />
                <FeatureCard
                  icon={<Search className="w-5 h-5" />}
                  title="Typosquat Analysis"
                  desc="Catching domains that are one typo away from popular sites"
                />
                <FeatureCard
                  icon={<AlertTriangle className="w-5 h-5" />}
                  title="Structural Red Flags"
                  desc="Detecting raw IPs, @ symbols, excessive subdomains, and more"
                />
                <FeatureCard
                  icon={<Link className="w-5 h-5" />}
                  title="Redirect Unrolling"
                  desc="Following shortened URLs and redirect chains to the real destination"
                />
                <FeatureCard
                  icon={<Globe className="w-5 h-5" />}
                  title="Domain Intelligence"
                  desc="WHOIS lookup to flag newly registered, short-lived domains"
                />
                <FeatureCard
                  icon={<Shield className="w-5 h-5" />}
                  title="Threat Intel APIs"
                  desc="Cross-referencing with Google Safe Browsing, VirusTotal, URLscan"
                />
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[var(--gray-100)] bg-white py-4">
        <div className="max-w-4xl mx-auto px-4 text-center text-xs text-[var(--gray-400)]">
          Phishr — URL Security Scanner
        </div>
      </footer>
    </div>
  );
}

/* ----------  Sub-components ---------- */

function FeatureCard({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white p-5 shadow-sm">
      <div className="w-9 h-9 rounded-md bg-[var(--ocean-50)] flex items-center justify-center text-[var(--ocean-600)] mb-3">
        {icon}
      </div>
      <h3 className="text-sm font-semibold text-[var(--gray-800)] mb-1">
        {title}
      </h3>
      <p className="text-xs text-[var(--gray-500)] leading-relaxed">{desc}</p>
    </div>
  );
}

/* ----------  Report ---------- */

function Report({ result }: { result: ScanResult }) {
  return (
    <div className="space-y-6">
      {/* Score Header */}
      <ScoreHeader result={result} />

      {/* URL Info */}
      <InfoPanel result={result} />

      {/* Findings */}
      {result.findings.length > 0 && <FindingsPanel findings={result.findings} />}

      {/* Redirect Chain */}
      {result.redirectChain.length > 1 && (
        <RedirectPanel chain={result.redirectChain} />
      )}

      {/* Domain Intelligence */}
      {result.domainIntel && <DomainPanel intel={result.domainIntel} />}

      {/* DNS Info */}
      {result.dns && <DnsPanel dns={result.dns} />}

      {/* Threat Intel */}
      {result.threatIntel.length > 0 && (
        <ThreatIntelPanel sources={result.threatIntel} />
      )}

      {/* Warnings */}
      {result.warnings.length > 0 && (
        <div className="rounded-lg border border-[var(--warning)] bg-[var(--warning-bg)] p-4 text-sm text-[var(--warning)]">
          <p className="font-medium mb-1">Scan Warnings</p>
          <ul className="list-disc list-inside space-y-0.5 text-xs">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ----------  Score header ---------- */

function ScoreHeader({ result }: { result: ScanResult }) {
  const { score, verdict } = result;

  let scoreColor = "text-[var(--safe)]";
  let scoreBg = "bg-[var(--safe-bg)]";
  let ringColor = "ring-green-200";
  let icon = <ShieldCheck className="w-8 h-8" />;

  if (score >= 80) {
    scoreColor = "text-[var(--danger)]";
    scoreBg = "bg-[var(--danger-bg)]";
    ringColor = "ring-red-200";
    icon = <ShieldAlert className="w-8 h-8" />;
  } else if (score >= 60) {
    scoreColor = "text-[var(--danger)]";
    scoreBg = "bg-[var(--danger-bg)]";
    ringColor = "ring-red-200";
    icon = <ShieldAlert className="w-8 h-8" />;
  } else if (score >= 35) {
    scoreColor = "text-[var(--warning)]";
    scoreBg = "bg-[var(--warning-bg)]";
    ringColor = "ring-yellow-200";
    icon = <AlertTriangle className="w-8 h-8" />;
  } else if (score >= 15) {
    scoreColor = "text-[var(--ocean-600)]";
    scoreBg = "bg-[var(--ocean-50)]";
    ringColor = "ring-blue-200";
    icon = <Shield className="w-8 h-8" />;
  }

  return (
    <div
      className={`rounded-lg p-6 ${scoreBg} border border-transparent shadow-sm`}
    >
      <div className="flex flex-col sm:flex-row items-center gap-5">
        {/* Ring Score */}
        <div
          className={`w-20 h-20 rounded-full ring-4 ${ringColor} flex items-center justify-center ${scoreBg}`}
        >
          <span className={`text-2xl font-bold ${scoreColor}`}>{score}</span>
        </div>

        <div className="text-center sm:text-left flex-1">
          <div className={`flex items-center justify-center sm:justify-start gap-2 ${scoreColor} mb-1`}>
            {icon}
            <span className="text-lg font-semibold">{verdict}</span>
          </div>
          <p className="text-sm text-[var(--gray-600)]">
            Risk score based on {result.findings.length} finding
            {result.findings.length !== 1 ? "s" : ""} across {categoryCount(result.findings)}{" "}
            detection categor{categoryCount(result.findings) !== 1 ? "ies" : "y"}
          </p>
        </div>

        <div className="text-xs text-[var(--gray-400)] whitespace-nowrap">
          {new Date(result.scannedAt).toLocaleString()}
        </div>
      </div>
    </div>
  );
}

function categoryCount(findings: Finding[]): number {
  return new Set(findings.map((f) => f.category)).size;
}

/* ----------  URL Info Panel ---------- */

function InfoPanel({ result }: { result: ScanResult }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)]">
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          URL Information
        </h3>
      </div>
      <div className="px-4 py-3 space-y-2 text-sm">
        <InfoRow label="Submitted URL" value={result.url} mono />
        {result.finalUrl && result.finalUrl !== result.url && (
          <InfoRow label="Final URL" value={result.finalUrl} mono />
        )}
        <InfoRow label="Hostname" value={result.hostname} mono />
      </div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-0.5 sm:gap-3">
      <span className="text-[var(--gray-500)] text-xs font-medium min-w-[120px]">
        {label}
      </span>
      <span
        className={`text-[var(--gray-800)] break-all ${
          mono ? "font-[family-name:var(--font-geist-mono)] text-xs" : ""
        }`}
      >
        {value}
      </span>
    </div>
  );
}

/* ----------  Findings Panel ---------- */

function FindingsPanel({ findings }: { findings: Finding[] }) {
  // Group by category
  const grouped: Partial<Record<FindingCategory, Finding[]>> = {};
  for (const f of findings) {
    if (!grouped[f.category]) grouped[f.category] = [];
    grouped[f.category]!.push(f);
  }

  const categoryLabels: Record<FindingCategory, { label: string; icon: React.ReactNode }> = {
    homoglyph: { label: "Homoglyph & Punycode", icon: <FileWarning className="w-4 h-4" /> },
    typosquat: { label: "Typosquatting", icon: <Search className="w-4 h-4" /> },
    structure: { label: "Structural Red Flags", icon: <AlertTriangle className="w-4 h-4" /> },
    redirect: { label: "Redirect Analysis", icon: <ExternalLink className="w-4 h-4" /> },
    "domain-intel": { label: "Domain Intelligence", icon: <Globe className="w-4 h-4" /> },
    dns: { label: "DNS Records", icon: <Server className="w-4 h-4" /> },
    "threat-intel": { label: "Threat Intelligence", icon: <Shield className="w-4 h-4" /> },
  };

  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)]">
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          Findings ({findings.length})
        </h3>
      </div>
      <div className="divide-y divide-[var(--gray-100)]">
        {(Object.keys(grouped) as FindingCategory[]).map((cat) => (
          <FindingGroup
            key={cat}
            icon={categoryLabels[cat]?.icon}
            label={categoryLabels[cat]?.label ?? cat}
            findings={grouped[cat] ?? []}
          />
        ))}
      </div>
    </div>
  );
}

function FindingGroup({
  icon,
  label,
  findings,
}: {
  icon: React.ReactNode;
  label: string;
  findings: Finding[];
}) {
  const [open, setOpen] = useState(true);

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-[var(--gray-50)] transition cursor-pointer"
      >
        <span className="text-[var(--ocean-600)]">{icon}</span>
        <span className="text-sm font-medium text-[var(--gray-700)] flex-1 text-left">
          {label}
        </span>
        <span className="text-xs text-[var(--gray-400)] mr-2">
          {findings.length}
        </span>
        {open ? (
          <ChevronUp className="w-4 h-4 text-[var(--gray-400)]" />
        ) : (
          <ChevronDown className="w-4 h-4 text-[var(--gray-400)]" />
        )}
      </button>
      {open && (
        <div className="px-4 pb-3 space-y-3">
          {findings.map((f, i) => (
            <FindingItem key={i} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingItem({ finding }: { finding: Finding }) {
  let severityColor = "bg-green-100 text-green-700";
  if (finding.severity >= 30) {
    severityColor = "bg-red-100 text-red-700";
  } else if (finding.severity >= 15) {
    severityColor = "bg-yellow-100 text-yellow-700";
  }

  return (
    <div className="rounded-md border border-[var(--gray-100)] p-3 bg-[var(--gray-50)]">
      <div className="flex items-start justify-between gap-2 mb-1.5">
        <h4 className="text-sm font-medium text-[var(--gray-800)]">
          {finding.label}
        </h4>
        <span
          className={`text-[10px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap ${severityColor}`}
        >
          +{finding.severity} pts
        </span>
      </div>
      <p className="text-xs text-[var(--gray-500)] leading-relaxed">
        {finding.description}
      </p>
    </div>
  );
}

/* ----------  Redirect Chain ---------- */

function RedirectPanel({ chain }: { chain: RedirectHop[] }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <History className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          Redirect Chain ({chain.length} hops)
        </h3>
      </div>
      <div className="px-4 py-3 space-y-2">
        {chain.map((hop, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="w-6 h-6 rounded-full bg-[var(--ocean-50)] text-[var(--ocean-600)] font-semibold flex items-center justify-center text-[10px] shrink-0">
              {i + 1}
            </span>
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                hop.statusCode >= 300 && hop.statusCode < 400
                  ? "bg-yellow-100 text-yellow-700"
                  : "bg-green-100 text-green-700"
              }`}
            >
              {hop.statusCode}
            </span>
            <span className="text-[var(--gray-600)] font-[family-name:var(--font-geist-mono)] break-all">
              {hop.url}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ----------  Domain Intelligence ---------- */

function DomainPanel({ intel }: { intel: NonNullable<ScanResult["domainIntel"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Globe className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          Domain Intelligence
        </h3>
      </div>
      <div className="px-4 py-3 space-y-2 text-sm">
        {intel.registrar && (
          <InfoRow label="Registrar" value={intel.registrar} />
        )}
        {intel.creationDate && (
          <InfoRow
            label="Registered"
            value={new Date(intel.creationDate).toLocaleDateString()}
          />
        )}
        {intel.expirationDate && (
          <InfoRow
            label="Expires"
            value={new Date(intel.expirationDate).toLocaleDateString()}
          />
        )}
        {intel.domainAgeDays !== null && (
          <InfoRow label="Domain Age" value={`${intel.domainAgeDays} days`} />
        )}
      </div>
    </div>
  );
}

/* ----------  DNS Panel ---------- */

function DnsPanel({ dns }: { dns: NonNullable<ScanResult["dns"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Server className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          DNS Records
        </h3>
      </div>
      <div className="px-4 py-3 space-y-2 text-sm">
        <InfoRow
          label="Resolves"
          value={dns.resolves ? "Yes" : "No"}
        />
        {dns.aRecords.length > 0 && (
          <InfoRow
            label="A Records"
            value={dns.aRecords.join(", ")}
            mono
          />
        )}
        <div className="flex items-center gap-2">
          <Mail className="w-3.5 h-3.5 text-[var(--gray-400)]" />
          <InfoRow
            label="MX Records"
            value={
              dns.mxRecords.length > 0
                ? dns.mxRecords.join(", ")
                : "None"
            }
            mono
          />
        </div>
      </div>
    </div>
  );
}

/* ----------  Threat Intelligence ---------- */

function ThreatIntelPanel({
  sources,
}: {
  sources: ScanResult["threatIntel"];
}) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Shield className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">
          Threat Intelligence
        </h3>
      </div>
      <div className="divide-y divide-[var(--gray-100)]">
        {sources.map((src, i) => (
          <div key={i} className="px-4 py-3 flex items-start gap-3">
            <span
              className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${
                src.flagged ? "bg-[var(--danger)]" : "bg-[var(--safe)]"
              }`}
            />
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-[var(--gray-800)]">
                  {src.source}
                </span>
                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    src.flagged
                      ? "bg-red-100 text-red-700"
                      : "bg-green-100 text-green-700"
                  }`}
                >
                  {src.flagged ? "FLAGGED" : "CLEAN"}
                </span>
              </div>
              {src.details && (
                <p className="text-xs text-[var(--gray-500)] mt-0.5">
                  {src.details}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
