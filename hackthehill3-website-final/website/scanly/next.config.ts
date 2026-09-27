import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  distDir: process.env.GUARDIA_DESKTOP === "1" ? ".next-desktop" : ".next",
  output: process.env.GUARDIA_PACKAGE === "1" ? "standalone" : undefined,
};
export default nextConfig;
