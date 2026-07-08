// Copy the canonical docs into public/ so Vite serves them from the SPA origin (dev + dist):
//   ../../AGENT_GUIDE.md                       -> public/AGENT_GUIDE.md   (rendered at /docs)
//   ../../por-risc0/host/src/openapi.json      -> public/openapi.json     (linked from /docs)
//
// Run automatically by `predev` / `prebuild` (see package.json), and by deploy build.sh via the
// npm build. Keeping ONE canonical copy of each (repo root guide, verifier's embedded openapi)
// and copying at build time means the served docs can't drift from what the service actually is.
import { copyFileSync, mkdirSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const pub = join(here, 'public')
mkdirSync(pub, { recursive: true })

const copies = [
  [join(here, '..', '..', 'AGENT_GUIDE.md'), join(pub, 'AGENT_GUIDE.md')],
  [join(here, '..', '..', 'por-risc0', 'host', 'src', 'openapi.json'), join(pub, 'openapi.json')],
]

for (const [src, dst] of copies) {
  if (!existsSync(src)) {
    console.warn(`[sync-docs] source missing, skipped: ${src}`)
    continue
  }
  copyFileSync(src, dst)
  console.log(`[sync-docs] ${src} -> ${dst}`)
}
