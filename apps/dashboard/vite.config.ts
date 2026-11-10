import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the dashboard runs on :5173 and forwards API calls to the approver API.
const api = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": api, "/approvals": api } },
  build: { target: "es2020", sourcemap: false, chunkSizeWarningLimit: 300 },
});
