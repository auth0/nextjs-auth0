import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Prevent webpack from trying to bundle undici (Node.js HTTP client)
  // Required for mTLS: undici uses Node.js built-ins that can't be bundled
  serverExternalPackages: ["undici"]
};

export default nextConfig;
