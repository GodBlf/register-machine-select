import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

export default defineConfig({
  plugins: [preact()],
  server: {
    host: "127.0.0.1",
    port: 8173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8318",
        changeOrigin: true,
      },
    },
  },
});
