import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { hostname } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
// The API's port, and optionally this server's own, so a second copy (the mock, say) can run beside the first:
// KEELSON_PORT=4417 KEELSON_WEB_PORT=5273 npm run dev -- --mock
const apiPort = Number(process.env.KEELSON_PORT) || 4317;
const webPort = Number(process.env.KEELSON_WEB_PORT) || 5173;
// The address the API listens on, when it isn't this machine only (`npm run dev -- --host`): this server listens there too,
// so other machines on the network open the same page. Bound to every interface, the API is still asked on loopback.
const host = process.env.KEELSON_HOST || undefined;
const everywhere = host === "0.0.0.0" || host === "::";
const apiHost = !host || everywhere ? "127.0.0.1" : host.includes(":") ? `[${host}]` : host;

export default defineConfig({
  root,
  base: "/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: fileURLToPath(new URL("../dist/web", import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: webPort,
    host,
    // Vite answers to addresses and localhost; this adds the machine's own name (my-laptop.local) for people who type that.
    allowedHosts: host ? [hostname().toLowerCase()] : undefined,
    // A port chosen on purpose must be the one used: drifting to the next free one could pair this page with another copy's API.
    strictPort: !!process.env.KEELSON_WEB_PORT,
    // Keep the browser's Host header (Vite's string shorthand rewrites it to the target). The API's CSRF check
    // compares Origin with Host, so a rewritten Host blocks every POST in development.
    proxy: { "/api": { target: `http://${apiHost}:${apiPort}`, changeOrigin: false } },
  },
});
