"use client";

import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
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
  Lock,
} from "lucide-react";
import type {
  ScanResult,
  Finding,
  FindingCategory,
  RedirectHop,
  SslHeadersInfo,
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
      <header className="border-b border-[var(--gray-100)] bg-white sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center gap-3">
          <Shield className="w-7 h-7 text-[var(--ocean-600)]" strokeWidth={2} />
          <h1 className="text-xl font-semibold text-[var(--gray-900)] tracking-tight">
            Phishr
          </h1>
        </div>
      </header>

      <main className="flex-1 flex flex-col">
        <section className="bg-[var(--ocean-50)] border-b border-[var(--ocean-100)]">
          <div className="max-w-4xl mx-auto px-4 py-12 md:py-16 text-center">
            <h2 className="text-2xl md:text-3xl font-semibold text-[var(--gray-900)] mb-3">
              Scan and analyse any URL.
            </h2>
            <p className="text-[var(--gray-500)] text-sm md:text-base max-w-xl mx-auto mb-8">
              Detect homoglyphs, typosquatting, malicious redirects, suspicious
              domains, and more — in seconds.
            </p>

            <ScanInput
              url={url}
              setUrl={setUrl}
              handleScan={handleScan}
              scanning={scanning}
              handleKeyDown={handleKeyDown}
            />

            {error && (
              <p className="mt-4 text-sm text-[var(--danger)]">{error}</p>
            )}
          </div>
        </section>

        <AnimatePresence mode="wait">
          {scanning && <ScanProgress key="progress" />}
          {result && !scanning && (
            <motion.section
              key="result"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              ref={resultRef}
              className="py-8 md:py-12"
            >
              <div className="max-w-4xl mx-auto px-4">
                <Report result={result} />
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {!result && !scanning && (
          <section className="py-12 md:py-16">
            <div className="max-w-4xl mx-auto px-4">
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
                {[
                  { icon: <FileWarning />, title: "Homoglyph Detection", desc: "Spotting lookalike Unicode characters" },
                  { icon: <Search />, title: "Typosquat Analysis", desc: "Catching domains one typo away" },
                  { icon: <AlertTriangle />, title: "Structural Red Flags", desc: "Detecting raw IPs and subdomains" },
                  { icon: <Link />, title: "Redirect Unrolling", desc: "Following chains to the destination" },
                  { icon: <Globe />, title: "Domain Intelligence", desc: "WHOIS lookup and domain age" },
                  { icon: <Shield />, title: "Threat Intel APIs", desc: "Cross-referencing global blacklists" },
                ].map((f, i) => (
                  <motion.div key={i} whileHover={{ y: -5 }}>
                    <FeatureCard {...f} />
                  </motion.div>
                ))}
              </div>
            </div>
          </section>
        )}
      </main>
      <footer className="border-t border-[var(--gray-100)] bg-white py-4">
        <div className="max-w-4xl mx-auto px-4 flex items-center justify-between text-xs text-[var(--gray-400)]">
          <span>Phishr — URL Security Scanner</span>
          <a
            href="https://github.com/dizzyx1/phishr"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub Repository"
            className="text-[var(--gray-400)] hover:text-[var(--gray-600)] transition-colors p-1 rounded-md"
          >
            <svg
              className="w-4 h-4"
              fill="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                fillRule="evenodd"
                d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                clipRule="evenodd"
              />
            </svg>
          </a>
        </div>
      </footer>
    </div>
  );
}

function ScanInput({
  url,
  setUrl,
  handleScan,
  scanning,
  handleKeyDown,
}: {
  url: string;
  setUrl: (v: string) => void;
  handleScan: () => void;
  scanning: boolean;
  handleKeyDown: (e: React.KeyboardEvent) => void;
}) {
  return (
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
        {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
        {scanning ? "Scanning..." : "Scan URL"}
      </button>
    </div>
  );
}

function ScanProgress() {
  const phases = [
    "Parsing & validating URL syntax...",
    "Analyzing homoglyphs & typosquatting...",
    "Tracing redirect chain & hops...",
    "Resolving DNS & MX configuration...",
    "Querying RDAP/WHOIS registry...",
    "Validating SSL/TLS & Security headers...",
    "Gathering site intelligence...",
  ];
  const [phaseIndex, setPhaseIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setPhaseIndex((prev) => (prev + 1) % phases.length);
    }, 800);
    return () => clearInterval(interval);
  }, [phases.length]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="max-w-xl mx-auto p-12 text-center"
    >
      <div className="relative h-2 bg-[var(--ocean-100)] rounded-full overflow-hidden mb-4">
        <motion.div
          className="absolute inset-y-0 left-0 bg-[var(--ocean-600)]"
          initial={{ width: "0%" }}
          animate={{ width: "95%" }}
          transition={{ duration: 5, ease: "linear" }}
        />
      </div>
      <p className="text-sm font-medium text-[var(--ocean-800)] animate-pulse">
        {phases[phaseIndex]}
      </p>
    </motion.div>
  );
}

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
      <h3 className="text-sm font-semibold text-[var(--gray-800)] mb-1">{title}</h3>
      <p className="text-xs text-[var(--gray-500)] leading-relaxed">{desc}</p>
    </div>
  );
}

function Report({ result }: { result: ScanResult }) {
  return (
    <div className="space-y-6">
      <ScoreHeader result={result} />
      {result.siteOverview && <SiteOverviewPanel overview={result.siteOverview} />}
      <InfoPanel result={result} />
      <SslHeadersPanel sslInfo={result.sslInfo} />
      {result.findings.length > 0 && <FindingsPanel findings={result.findings} />}
      {result.redirectChain.length > 1 && <RedirectPanel chain={result.redirectChain} />}
      {result.domainIntel && <DomainPanel intel={result.domainIntel} />}
      {result.dns && <DnsPanel dns={result.dns} />}
      {result.threatIntel.length > 0 && <ThreatIntelPanel sources={result.threatIntel} />}
    </div>
  );
}

function ScoreHeader({ result }: { result: ScanResult }) {
  const { score, verdict } = result;

  const colors = {
    Dangerous: {
      color: "text-[var(--danger)]",
      bg: "bg-[var(--danger-bg)]",
      ring: "ring-red-200",
      icon: <ShieldAlert className="w-8 h-8" />,
    },
    "High Risk": {
      color: "text-[var(--danger)]",
      bg: "bg-[var(--danger-bg)]",
      ring: "ring-red-200",
      icon: <ShieldAlert className="w-8 h-8" />,
    },
    "Moderate Risk": {
      color: "text-[var(--warning)]",
      bg: "bg-[var(--warning-bg)]",
      ring: "ring-yellow-200",
      icon: <AlertTriangle className="w-8 h-8" />,
    },
    "Low Risk": {
      color: "text-[var(--ocean-600)]",
      bg: "bg-[var(--ocean-50)]",
      ring: "ring-blue-200",
      icon: <Shield className="w-8 h-8" />,
    },
    Safe: {
      color: "text-[var(--safe)]",
      bg: "bg-[var(--safe-bg)]",
      ring: "ring-green-200",
      icon: <ShieldCheck className="w-8 h-8" />,
    },
  };
  const { color, bg, ring, icon } = colors[verdict] || colors.Safe;

  return (
    <motion.div
      initial={{ scale: 0.98, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      className={`rounded-lg p-6 ${bg} shadow-sm border border-transparent`}
    >
      <div className="flex flex-col sm:flex-row items-center gap-5">
        <div
          className={`w-20 h-20 rounded-full ring-4 ${ring} flex items-center justify-center bg-white shadow-inner`}
        >
          <span className={`text-2xl font-bold ${color}`}>{score}</span>
        </div>
        <div className="text-center sm:text-left flex-1">
          <div className={`flex items-center justify-center sm:justify-start gap-2 ${color} mb-1`}>
            {icon}
            <span className="text-lg font-semibold">{verdict}</span>
          </div>
          <p className="text-sm text-[var(--gray-600)]">Based on {result.findings.length} findings</p>
        </div>
        <div className="text-xs text-[var(--gray-400)]">{new Date(result.scannedAt).toLocaleString()}</div>
      </div>
    </motion.div>
  );
}

function SiteOverviewPanel({ overview }: { overview: NonNullable<ScanResult["siteOverview"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Globe className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">Website Overview & Intelligence</h3>
      </div>
      <div className="px-4 py-3 text-sm">
        <p className="font-semibold text-[var(--gray-800)] mb-1">{overview.title}</p>
        <p className="text-[var(--gray-600)] mb-3 leading-relaxed text-xs sm:text-sm">{overview.description}</p>
        <div className="flex flex-wrap gap-2">
          {overview.category && (
            <span className="px-2.5 py-0.5 rounded-full bg-[var(--ocean-50)] text-[var(--ocean-700)] text-[11px] font-medium border border-[var(--ocean-100)]">
              {overview.category}
            </span>
          )}
          <span className="px-2.5 py-0.5 rounded-full bg-[var(--gray-100)] text-[var(--gray-600)] text-[11px] font-medium">
            Source: {overview.source}
          </span>
        </div>
      </div>
    </div>
  );
}

function InfoPanel({ result }: { result: ScanResult }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm p-4 space-y-2 text-xs sm:text-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1 border-b border-[var(--gray-50)]">
        <span className="text-[var(--gray-500)]">Scanned URL</span>
        <span className="font-mono text-[var(--gray-800)] break-all">{result.url}</span>
      </div>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1 border-b border-[var(--gray-50)]">
        <span className="text-[var(--gray-500)]">Target Hostname</span>
        <span className="font-mono font-medium text-[var(--gray-800)]">{result.hostname}</span>
      </div>
      {result.finalUrl && result.finalUrl !== result.url && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 py-1">
          <span className="text-[var(--gray-500)]">Final Destination</span>
          <span className="font-mono text-[var(--gray-800)] break-all">{result.finalUrl}</span>
        </div>
      )}
    </div>
  );
}

function SslHeadersPanel({ sslInfo }: { sslInfo: SslHeadersInfo | null }) {
  if (!sslInfo) return null;
  const checks = [
    { label: "HTTPS Enabled", val: sslInfo.isHttps },
    { label: "HSTS Header", val: sslInfo.hasHsts },
    { label: "CSP Header", val: sslInfo.hasCsp },
    { label: "X-Frame-Options", val: sslInfo.hasXFrameOptions },
    { label: "X-Content-Type", val: sslInfo.hasXContentTypeOptions },
  ];
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-[var(--ocean-600)]" />
          <h3 className="text-sm font-semibold text-[var(--gray-700)]">Security Headers & SSL Configuration</h3>
        </div>
        {sslInfo.serverHeader && (
          <span className="text-[11px] text-[var(--gray-400)] font-mono">
            Server: {sslInfo.serverHeader}
          </span>
        )}
      </div>
      <div className="px-4 py-3 grid grid-cols-2 sm:grid-cols-3 gap-3">
        {checks.map((c, i) => (
          <div key={i} className="flex items-center gap-2 text-xs text-[var(--gray-700)] font-medium">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                c.val ? "bg-[var(--safe)] shadow-[0_0_6px_rgba(22,163,74,0.4)]" : "bg-[var(--gray-300)]"
              }`}
            />
            {c.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsPanel({ findings }: { findings: Finding[] }) {
  const categories: Record<FindingCategory, string> = {
    homoglyph: "Homoglyphs & Character Spoofing",
    typosquat: "Typosquatting & Lookalike Domains",
    structure: "URL Structural Indicators",
    redirect: "Redirect & Cloaking Behavior",
    "domain-intel": "Domain Registration & Age",
    dns: "DNS & Mail Exchange (MX) Configuration",
    "threat-intel": "Threat Intelligence Blacklists",
    ssl: "SSL/TLS & Security Headers",
  };

  const grouped = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    acc[f.category] = acc[f.category] || [];
    acc[f.category].push(f);
    return acc;
  }, {});

  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">Detailed Findings ({findings.length})</h3>
      </div>
      <div className="divide-y divide-[var(--gray-100)]">
        {(Object.keys(grouped) as FindingCategory[]).map((cat) => (
          <FindingGroup key={cat} title={categories[cat] || cat} findings={grouped[cat]} />
        ))}
      </div>
    </div>
  );
}

function FindingGroup({ title, findings }: { title: string; findings: Finding[] }) {
  const [open, setOpen] = useState(true);

  return (
    <div className="p-4">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between text-left font-semibold text-xs text-[var(--gray-700)] mb-2"
      >
        <span>
          {title} ({findings.length})
        </span>
        {open ? <ChevronUp className="w-3.5 h-3.5 text-[var(--gray-400)]" /> : <ChevronDown className="w-3.5 h-3.5 text-[var(--gray-400)]" />}
      </button>

      {open && (
        <div className="space-y-2.5 mt-2">
          {findings.map((f) => (
            <FindingItem key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingItem({ finding }: { finding: Finding }) {
  const severityBadge = (sev: number) => {
    if (sev >= 40) return "bg-red-50 text-red-700 border-red-200";
    if (sev >= 20) return "bg-yellow-50 text-yellow-700 border-yellow-200";
    return "bg-blue-50 text-blue-700 border-blue-200";
  };

  return (
    <div className="p-3 rounded-md bg-[var(--gray-50)] border border-[var(--gray-100)] text-xs">
      <div className="flex items-center justify-between mb-1">
        <span className="font-medium text-[var(--gray-900)]">{finding.label}</span>
        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${severityBadge(finding.severity)}`}>
          +{finding.severity} Risk
        </span>
      </div>
      <p className="text-[var(--gray-600)] leading-relaxed">{finding.description}</p>
    </div>
  );
}

function RedirectPanel({ chain }: { chain: RedirectHop[] }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Link className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">Redirect Chain ({chain.length} Hops)</h3>
      </div>
      <div className="p-4 space-y-3">
        {chain.map((hop, i) => (
          <div key={i} className="flex items-start gap-3 text-xs">
            <span className="px-2 py-0.5 rounded bg-[var(--gray-100)] text-[var(--gray-700)] font-mono font-medium">
              {hop.statusCode || "Final"}
            </span>
            <span className="font-mono text-[var(--gray-800)] break-all mt-0.5">{hop.url}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DomainPanel({ intel }: { intel: NonNullable<ScanResult["domainIntel"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <History className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">Domain Intelligence (RDAP/WHOIS)</h3>
      </div>
      <div className="p-4 grid sm:grid-cols-2 gap-3 text-xs">
        <div>
          <span className="text-[var(--gray-500)] block mb-0.5">Registrar</span>
          <span className="font-medium text-[var(--gray-800)]">{intel.registrar || "Not disclosed / Private"}</span>
        </div>
        <div>
          <span className="text-[var(--gray-500)] block mb-0.5">Domain Age</span>
          <span className="font-medium text-[var(--gray-800)]">
            {intel.domainAgeDays !== null ? `${intel.domainAgeDays} days old` : "Unknown"}
          </span>
        </div>
        <div>
          <span className="text-[var(--gray-500)] block mb-0.5">Creation Date</span>
          <span className="font-medium text-[var(--gray-800)]">
            {intel.creationDate ? new Date(intel.creationDate).toLocaleDateString() : "Unknown"}
          </span>
        </div>
        <div>
          <span className="text-[var(--gray-500)] block mb-0.5">Expiration Date</span>
          <span className="font-medium text-[var(--gray-800)]">
            {intel.expirationDate ? new Date(intel.expirationDate).toLocaleDateString() : "Unknown"}
          </span>
        </div>
      </div>
    </div>
  );
}

function DnsPanel({ dns }: { dns: NonNullable<ScanResult["dns"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Server className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">DNS & Mail Exchange (MX)</h3>
      </div>
      <div className="p-4 space-y-3 text-xs">
        <div>
          <span className="text-[var(--gray-500)] block mb-1">A Records (IP Addresses)</span>
          <div className="flex flex-wrap gap-2">
            {dns.aRecords.length > 0 ? (
              dns.aRecords.map((ip, i) => (
                <span key={i} className="font-mono bg-[var(--gray-50)] border border-[var(--gray-100)] px-2 py-0.5 rounded">
                  {ip}
                </span>
              ))
            ) : (
              <span className="text-[var(--gray-400)]">None resolved</span>
            )}
          </div>
        </div>
        <div>
          <span className="text-[var(--gray-500)] block mb-1">MX Records (Mail Servers)</span>
          <div className="flex flex-wrap gap-2">
            {dns.mxRecords.length > 0 ? (
              dns.mxRecords.map((mx, i) => (
                <span key={i} className="font-mono bg-[var(--gray-50)] border border-[var(--gray-100)] px-2 py-0.5 rounded">
                  {mx}
                </span>
              ))
            ) : (
              <span className="text-[var(--gray-400)]">No MX records configured</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ThreatIntelPanel({ sources }: { sources: NonNullable<ScanResult["threatIntel"]> }) {
  return (
    <div className="rounded-lg border border-[var(--gray-100)] bg-white shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-[var(--gray-50)] border-b border-[var(--gray-100)] flex items-center gap-2">
        <Shield className="w-4 h-4 text-[var(--ocean-600)]" />
        <h3 className="text-sm font-semibold text-[var(--gray-700)]">Threat Intelligence Blacklists</h3>
      </div>
      <div className="p-4 divide-y divide-[var(--gray-50)]">
        {sources.map((s, i) => (
          <div key={i} className="py-3 first:pt-0 last:pb-0 text-xs">
            <div className="flex items-center justify-between mb-1">
              <span className="font-medium text-[var(--gray-800)]">{s.source}</span>
              <span
                className={`px-2 py-0.5 rounded font-semibold text-[10px] ${
                  s.flagged ? "bg-red-50 text-red-700 border border-red-200" : "bg-green-50 text-green-700 border border-green-200"
                }`}
              >
                {s.flagged ? "MALICIOUS" : "CLEAN"}
              </span>
            </div>
            {s.flagged && s.details && (
              <div className="text-[var(--gray-500)] mt-1.5 leading-relaxed bg-[var(--gray-50)] p-2 rounded border border-[var(--gray-100)]">
                {s.details}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
