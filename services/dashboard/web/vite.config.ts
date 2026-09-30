// SPDX-License-Identifier: AGPL-3.0-only

import { writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'

const __dirname = dirname(fileURLToPath(import.meta.url))

// The console is served by the Go binary from an embed.FS, so the build output is
// plain static files with no server runtime of its own.
// The Go binary embeds this directory, and `go:embed` fails at *compile* time if it
// does not exist — long before the friendly "run npm run build" message in spa.go can
// be reached. So a marker file is committed to keep the directory present in a fresh
// clone, and `emptyOutDir` would delete it on every build. This puts it back.
function keepOutDir(): Plugin {
  return {
    name: 'lazaret-keep-outdir',
    closeBundle() {
      writeFileSync(resolve(__dirname, 'dist/.gitkeep'), '')
    },
  }
}

export default defineConfig({
  plugins: [vue(), keepOutDir()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true, // AGPL: the corresponding source travels with the minified bundle.

    // Vite's module-preload polyfill is injected as an *inline* <script>, which a
    // `script-src 'self'` policy refuses — the app then fails to boot with nothing in
    // the console but a CSP violation. Every browser this console supports handles
    // modulepreload natively, so the polyfill buys nothing and costs the policy.
    modulePreload: { polyfill: false },

    rollupOptions: {
      output: {
        // Content-hashed, so the Go handler can serve them immutable for a year while
        // index.html itself stays no-store.
        entryFileNames: 'assets/[name].[hash].js',
        chunkFileNames: 'assets/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash][extname]',
      },
    },
  },

  // `npm run dev` serves the UI and forwards everything stateful to the Go dashboard,
  // so the dev server never needs its own copy of auth.
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ['/api', '/auth', '/messages'].map((p) => [p, { target: 'http://localhost:8740', changeOrigin: true }]),
    ),
  },
})
