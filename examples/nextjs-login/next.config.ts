import type { NextConfig } from "next";

const config: NextConfig = {
  // The sign-in page talks to IAMKit from the browser; nothing else needs
  // to leave the server.
  poweredByHeader: false,
};

export default config;
