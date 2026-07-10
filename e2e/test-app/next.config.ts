import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  turbopack: {
    root: __dirname,
  },
  allowedDevOrigins: ["piyushkumar.acmetest.org"],
};

export default nextConfig;
