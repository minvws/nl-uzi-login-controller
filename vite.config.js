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
        {
          src: resolve(__dirname, 'node_modules','swagger-ui-dist','swagger-ui-bundle.js'),
          dest: resolve(__dirname,'static','assets')
        },
        {
          src: resolve(__dirname, 'node_modules','swagger-ui-dist','swagger-ui.css'),
          dest: resolve(__dirname,'static','assets')
        },
        {
          src: resolve(__dirname, 'node_modules','redoc','bundles','redoc.standalone.js'),
          dest: resolve(__dirname,'static','assets')
        }
      ]
    })
  ]
})
