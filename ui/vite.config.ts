import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

// "preview" mode builds a single self-contained HTML file running on
// sample data, for sharing the design without an appliance.
export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(mode === 'preview' ? [viteSingleFile()] : [])],
  // `npm run dev` sends API calls to the Go backend; `make mock` starts
  // it (opf -mock) on this address.
  server: { proxy: { '/api': 'http://127.0.0.1:18080' } },
  build: { outDir: mode === 'preview' ? 'dist-preview' : 'dist' },
}));
