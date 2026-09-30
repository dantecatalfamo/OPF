import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';

// Node's, without pulling in @types/node for one variable.
declare const process: { env: Record<string, string | undefined> };

// "preview" mode builds a single self-contained HTML file running on
// sample data, for sharing the design without an appliance.
export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(mode === 'preview' ? [viteSingleFile()] : [])],
  // The Go generators in WebAssembly, only in the offline preview build;
  // every other build gets a stub, so the real UI never ships them.
  resolve: {
    alias: { '@wasmgen': new URL(mode === 'preview' ? './src/lib/wasmGen.ts' : './src/lib/wasmGenStub.ts', import.meta.url).pathname },
  },
  // `npm run dev` sends API calls to the Go backend; `make mock` starts
  // it (opf -mock) on this address. OPF_API points it elsewhere, for
  // running a second mock alongside.
  server: { proxy: { '/api': process.env.OPF_API ?? 'http://127.0.0.1:18080' } },
  build: { outDir: mode === 'preview' ? 'dist-preview' : 'dist' },
}));
