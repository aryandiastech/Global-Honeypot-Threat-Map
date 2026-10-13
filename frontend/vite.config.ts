import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  // The map libraries are large single chunks, loaded lazily (only the one in use).
  build: {
    chunkSizeWarningLimit: 2000,
  },
  // MapLibre's worker is an ES module (it imports a shared chunk).
  worker: {
    format: "es",
  },
});
