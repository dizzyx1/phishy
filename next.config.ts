import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Ensure server-only Node.js modules don't try to bundle on the client
  serverExternalPackages: ["whois-json"],
};

export default nextConfig;
