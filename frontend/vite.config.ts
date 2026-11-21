import { defineConfig } from 'vite';

// Development only. Go's EDR_ADDR defaults to 127.0.0.1:8080. The Vite
// dev server is localhost-only and must never expose the lab bearer API.
export default defineConfig({
  server: {
    host: '127.0.0.1',
    strictPort: true,
    proxy: { '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false } },
  },
  build: { outDir: 'dist', rollupOptions: { input: { soc: 'index.html', companion: 'local-companion.html' } } },
});
