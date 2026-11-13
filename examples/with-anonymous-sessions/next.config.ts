import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Pin the workspace root so Turbopack resolves modules from THIS example's
  // node_modules. Without this, Next infers the root from a stray lockfile
  // higher up the tree (e.g. ~/src/package-lock.json) and resolves React/SWR
  // from the wrong store, yielding two module instances and an RSC SWRConfig
  // crash ("Cannot read properties of undefined (reading 'provider')").
  turbopack: {
    root: __dirname
  }
};

export default nextConfig;
