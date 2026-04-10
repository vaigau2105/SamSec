import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required for Docker — copies only what's needed to run
  output: "standalone",

  // Suppress hydration warnings from browser extensions
  reactStrictMode: true,
};

export default nextConfig;