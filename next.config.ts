import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ensure server-only Node.js modules (dns, whois-json, etc.) don't try to bundle on the client
  serverExternalPackages: ["whois-json", "dns"],
};

export default nextConfig;
