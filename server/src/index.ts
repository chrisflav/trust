import express from 'express'
import { migrate, waitForDatabase } from './db'
import { routes } from './routes'

const PORT = Number(process.env.PORT ?? 8080)

/** Refuse to start misconfigured rather than fail confusingly on first use. */
function checkConfiguration(): string[] {
  const problems: string[] = []
  if (!process.env.DATABASE_URL) problems.push('DATABASE_URL is not set')
  const secret = process.env.SESSION_SECRET ?? ''
  if (secret.length < 32) {
    problems.push('SESSION_SECRET must be at least 32 characters (openssl rand -hex 32)')
  }
  for (const name of ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'PUBLIC_URL']) {
    if (!process.env[name]) problems.push(`${name} is not set`)
  }
  return problems
}

async function main(): Promise<void> {
  const problems = checkConfiguration()
  if (problems.length > 0) {
    for (const problem of problems) console.error(`config: ${problem}`)
    console.error('see docker/.env.example')
    process.exit(1)
  }

  await waitForDatabase()
  await migrate()

  const app = express()
  app.use(express.json({ limit: '256kb' }))

  // The frontend is served from somewhere else, so it needs to be allowed to
  // call this with credentials; a single named origin rather than `*`, since
  // `*` and cookies are mutually exclusive for good reason.
  const origin = process.env.APP_URL
  app.use((request, response, next) => {
    if (origin) {
      response.setHeader('Access-Control-Allow-Origin', origin)
      response.setHeader('Access-Control-Allow-Credentials', 'true')
      response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
      response.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
    }
    if (request.method === 'OPTIONS') {
      response.status(204).end()
      return
    }
    next()
  })

  app.use(routes)
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(error)
    res.status(500).json({ error: 'internal error' })
  })

  app.listen(PORT, () => console.log(`trust server listening on :${PORT}`))
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
