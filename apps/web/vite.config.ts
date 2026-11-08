import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// En desarrollo (yarn dev:web) las llamadas a /api se redirigen a la API local.
// En Docker, nginx hace este proxy (ver nginx.conf).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { '/api': { target: process.env.VITE_API_URL ?? 'http://localhost:3000', changeOrigin: true } },
  },
  build: {
    chunkSizeWarningLimit: 1200,
  },
});
