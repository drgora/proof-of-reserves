import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api to the prover service (por_service) so the browser
// sees a single origin (no CORS). In Docker the target is overridden via
// API_PROXY (e.g. http://service:8090); locally it defaults to localhost.
const API_PROXY = process.env.API_PROXY || 'http://127.0.0.1:8090'

// Vite blocks requests whose Host header isn't allowlisted (DNS-rebinding guard).
// Behind Railway the Host is the generated *.up.railway.app domain, so allow it by
// default (a leading "." matches the domain and all its subdomains). Override or
// extend with ALLOWED_HOSTS (comma-separated) when serving a custom domain, or set
// ALLOWED_HOSTS=true to disable the check entirely.
const rawHosts = process.env.ALLOWED_HOSTS
const allowedHosts =
  rawHosts === 'true'
    ? true
    : rawHosts
      ? rawHosts.split(',').map((s) => s.trim()).filter(Boolean)
      : ['.up.railway.app']

export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // bind 0.0.0.0 so the container is reachable from the host
    port: 5173,
    allowedHosts,
    proxy: { '/api': API_PROXY },
  },
})
