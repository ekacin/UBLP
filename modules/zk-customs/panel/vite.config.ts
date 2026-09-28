import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind every interface, not just Vite's default — the panel's base URL and this README
    // both use 127.0.0.1, same reasoning as incoterms-escrow/panel's vite.config.ts.
    host: true,
  },
});
