import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Stops `next dev` writing AGENTS.md and CLAUDE.md into this folder.
  agentRules: false
};

export default nextConfig;
