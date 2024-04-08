import { resolve } from 'path'
import { defineConfig } from 'vite';
import { viteStaticCopy } from 'vite-plugin-static-copy'
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  base: '',
  build: {
    rollupOptions: {
      input: {
        'app.js': resolve(__dirname, 'resources', 'js', 'app.js'),
        'app.css': resolve(__dirname, 'resources', 'css', 'app.scss'),
      },
    },
    outDir: '',
    assetsDir: 'static/assets',
    manifest: 'static/assets/manifest.json',
    emptyOutDir: false,
  },
  plugins: [
    nodePolyfills({
      include: [
          'url',
          'events',
          'https',
          'http',
          'util',
          'querystring',
      ],
    }),
    viteStaticCopy({
      targets: [

      ]
    })
  ]
})
