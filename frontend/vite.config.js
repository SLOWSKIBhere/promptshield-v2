import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(() => {
  const offlineFixture = process.env.VITE_OFFLINE_FIXTURE === 'true'

  return {
    plugins: [
      react(),
      ...(offlineFixture ? [{
        name: 'offline-html',
        transformIndexHtml(html) {
          return html.replace(/\s*<link[^>]+href="https:\/\/fonts\.(?:googleapis|gstatic)\.com[^>]*>/g, '')
        },
      }] : []),
    ],
    server: {
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ''),
        },
      },
    },
  }
})
