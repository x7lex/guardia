import type { NextConfig } from "next";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export', // Outputs a static "out" folder
  images: { unoptimized: true }, // Electron handles local files directly
  typescript: {
    ignoreBuildErrors: true
  }
};
export default nextConfig;
