import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api to the prover service (por_service) so the browser
// sees a single origin (no CORS). In Docker the target is overridden via
// API_PROXY (e.g. http://service:8090); locally it defaults to localhost.
const API_PROXY = process.env.API_PROXY || 'http://127.0.0.1:8090'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // bind 0.0.0.0 so the container is reachable from the host
    port: 5173,
    proxy: { '/api': API_PROXY },
  },
})
