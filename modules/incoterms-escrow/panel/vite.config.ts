import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind every interface, not just Vite's default (which on some hosts resolves to IPv6
    // loopback only) — the panel's own default agent URL, the instance switcher, and this
    // README all use 127.0.0.1, so the dev server itself must actually be reachable there too,
    // not just via `localhost`.
    host: true,
  },
});
