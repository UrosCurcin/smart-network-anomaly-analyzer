import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the FastAPI backend through the "/api" prefix.
// Vite's dev server proxies that prefix straight to uvicorn, stripping the
// prefix on the way through, so the browser never makes a cross-origin
// request during development and we don't have to fight CORS configuration.
//
// Change `target` here if you run the API on a different host or port than
// the default `sn-analyzer-api` command uses (127.0.0.1:8000).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
