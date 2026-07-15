import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Built to ./dist as static assets; the control plane (al_core.app) serves them
// at /dashboard on control-net. Base is relative so it works under that path.
// In dev, /api is proxied to a running `al dashboard` (default :8899).
export default defineConfig({
  plugins: [react()],
  // Served by the control plane under /dashboard/ (StaticFiles mount).
  base: '/dashboard/',
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 900 },
  server: {
    port: 5273,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8899', changeOrigin: true },
      '/healthz': { target: 'http://127.0.0.1:8899', changeOrigin: true },
    },
  },
})
