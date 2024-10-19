import { defineConfig } from 'vite'
import nacl from 'tweetnacl';

export default defineConfig({
  build: {
    outDir: 'dist',
  },
  rollupOptions: {
    // If tweetnacl isn't getting bundled, try forcing Vite to include it:
    external: ['tweetnacl'],
  },
})