import express from 'express'
import { checkConfiguration, loadConfig, type Config } from './config'
import { createAuth } from './auth'
import { createRoutes } from './routes'
import { openDb, waitForDatabase } from './store/db'
import { Store } from './store'
import { announcePeer } from './federation/service'

/**
 * Paths any node may read, from anywhere, without a session.
 *
 * Everything they return is either public by construction or signed, so the
 * useful CORS answer is `*` — and `*` is only usable *because* they need no
 * credentials.  The rest of the API keeps the single named origin it has
 * always had, since `*` and cookies are mutually exclusive for good reason.
 */
const PUBLIC_PREFIXES = ['/api/federation', '/api/peers', '/api/certificates', '/api/key']

function isPublicRead(request: express.Request): boolean {
  return (
    request.method === 'GET' &&
    PUBLIC_PREFIXES.some((prefix) => request.path === prefix || request.path.startsWith(`${prefix}/`))
  )
}

export function createApp(config: Config, store: Store): express.Express {
  const app = express()
  app.use(express.json({ limit: '1mb' }))

  app.use((request, response, next) => {
    if (isPublicRead(request)) {
      response.setHeader('Access-Control-Allow-Origin', '*')
    } else if (config.appUrl) {
      response.setHeader('Access-Control-Allow-Origin', config.appUrl)
      response.setHeader('Access-Control-Allow-Credentials', 'true')
    }
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
    if (request.method === 'OPTIONS') {
      response.status(204).end()
      return
    }
    next()
  })

  app.use(createRoutes(config, store, createAuth(config, store)))
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(error)
    res.status(500).json({ error: 'internal error' })
  })
  return app
}

export async function openStore(config: Config): Promise<Store> {
  const db = await openDb({
    kind: config.store,
    connectionString: config.databaseUrl,
    path: config.sqlitePath,
  })
  if (config.store === 'pg') await waitForDatabase(db)
  const store = new Store(db)
  await store.ready()
  return store
}

/** Record the peers the operator configured, without ever querying them yet. */
async function adoptSeeds(config: Config, store: Store): Promise<void> {
  for (const seed of config.seeds) {
    const existing = await store.peerByUrl(seed)
    if (existing) continue
    // A seed is the operator's own decision, so it is queried from the start —
    // unlike anything discovered, which only ever becomes a candidate.
    await store.upsertPeer(seed, '', 'seed')
    // Best effort: a seed that is down at boot is still a seed.
    void announcePeer(store, config, seed).catch(() => undefined)
  }
}

async function main(): Promise<void> {
  const config = loadConfig()
  const problems = checkConfiguration(config)
  if (problems.length > 0) {
    for (const problem of problems) console.error(`config: ${problem}`)
    console.error('see docker/.env.example')
    process.exit(1)
  }

  const store = await openStore(config)
  await adoptSeeds(config, store)

  createApp(config, store).listen(config.port, () => {
    const where = config.store === 'sqlite' ? config.sqlitePath : 'postgres'
    console.log(
      `trust server listening on :${config.port} (${config.local ? 'local' : 'public'}, ${where})`,
    )
  })
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
