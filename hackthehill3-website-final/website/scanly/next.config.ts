import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  distDir: process.env.GUARDIA_DESKTOP === "1" ? ".next-desktop" : ".next",
};
export default nextConfig;
