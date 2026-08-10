/**
 * Everything the process reads from its environment, in one place.
 *
 * Scattered `process.env` reads make it impossible to answer "what does this
 * node do" without grepping, and — more practically — impossible to run two
 * nodes in one test process.  Configuration is resolved once, into a value.
 */

export type StoreKind = 'pg' | 'sqlite'

/** The limits of §8 of FEDERATION.md, all of them defences against a bad peer. */
export interface Policy {
  maxDepth: number
  maxEntries: number
  maxResponseBytes: number
  peerTimeoutMs: number
  queryBudgetMs: number
  remoteTtlS: number
  maxViaLength: number
  /** Whether a newly discovered peer is queried, or only recorded. */
  autodiscover: boolean
  /** Allow http and private addresses.  For local mode and tests only. */
  allowPrivate: boolean
}

export interface Config {
  port: number
  /** This node's own externally reachable base URL; its name in `via` chains. */
  publicUrl: string
  /** Where the frontend runs, and the one origin allowed to send cookies. */
  appUrl: string
  name: string
  /** Local mode: one user, SQLite, no OAuth, no public surface. */
  local: boolean
  store: StoreKind
  databaseUrl: string
  sqlitePath: string
  sessionSecret: string
  cookieSecure: boolean
  github: { clientId: string; clientSecret: string }
  seeds: string[]
  /**
   * Bearer token for the handful of operations that are the operator's, not a
   * user's: promoting a peer, blocking one, forcing a pull.  Unset means those
   * endpoints are closed rather than open — a federation control plane that
   * defaults to reachable is not one.
   */
  adminToken: string
  policy: Policy
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const num = (name: string, fallback: number): number => {
    const raw = env[name]
    if (raw === undefined || raw === '') return fallback
    const value = Number(raw)
    return Number.isFinite(value) && value >= 0 ? value : fallback
  }
  const bool = (name: string, fallback: boolean): boolean => {
    const raw = env[name]
    if (raw === undefined || raw === '') return fallback
    return raw === 'true' || raw === '1' || raw === 'yes'
  }
  const list = (name: string): string[] =>
    (env[name] ?? '')
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)

  const local = bool('TRUST_LOCAL', false)
  const port = num('PORT', local ? 8090 : 8080)
  return {
    port,
    publicUrl: (env.PUBLIC_URL ?? (local ? `http://127.0.0.1:${port}` : '')).replace(/\/+$/, ''),
    appUrl: (env.APP_URL ?? '').replace(/\/+$/, ''),
    name: env.NODE_NAME ?? (local ? 'local' : ''),
    local,
    store: (env.STORE as StoreKind | undefined) ?? (local ? 'sqlite' : 'pg'),
    databaseUrl: env.DATABASE_URL ?? '',
    sqlitePath: env.SQLITE_PATH ?? defaultSqlitePath(env),
    // In local mode nothing is exposed and there is nobody to forge a session
    // against, so a generated secret beats refusing to start over a missing one.
    sessionSecret: env.SESSION_SECRET ?? '',
    cookieSecure: bool('COOKIE_SECURE', false),
    github: { clientId: env.GITHUB_CLIENT_ID ?? '', clientSecret: env.GITHUB_CLIENT_SECRET ?? '' },
    seeds: list('FEDERATION_SEEDS'),
    adminToken: env.ADMIN_TOKEN ?? '',
    policy: {
      maxDepth: num('FEDERATION_MAX_DEPTH', 2),
      maxEntries: num('FEDERATION_MAX_ENTRIES', 500),
      maxResponseBytes: num('FEDERATION_MAX_RESPONSE_BYTES', 2 * 1024 * 1024),
      peerTimeoutMs: num('FEDERATION_PEER_TIMEOUT_MS', 4000),
      queryBudgetMs: num('FEDERATION_QUERY_BUDGET_MS', 8000),
      remoteTtlS: num('FEDERATION_REMOTE_TTL_S', 300),
      maxViaLength: num('FEDERATION_MAX_VIA', 8),
      autodiscover: bool('FEDERATION_AUTODISCOVER', false),
      // Local mode pulls from other things on the same machine, so the private
      // address rule would forbid exactly its normal use.  A public deployment
      // has to opt in deliberately.
      allowPrivate: bool('FEDERATION_ALLOW_PRIVATE', local),
    },
  }
}

/** `~/.local/share/trust/trust.db`, or `$XDG_DATA_HOME` when it is set. */
function defaultSqlitePath(env: NodeJS.ProcessEnv): string {
  const base = env.XDG_DATA_HOME || (env.HOME ? `${env.HOME}/.local/share` : '.')
  return `${base}/trust/trust.db`
}

/**
 * Refuse to start misconfigured rather than fail confusingly on first use.
 *
 * Local mode needs almost none of this: there is no OAuth round trip to get
 * wrong and no origin to mismatch, and demanding a GitHub app before someone
 * can keep their own judgements in their own database would be absurd.
 */
export function checkConfiguration(config: Config): string[] {
  const problems: string[] = []
  if (config.store === 'pg' && !config.databaseUrl) problems.push('DATABASE_URL is not set')
  if (!config.local) {
    if (config.sessionSecret.length < 32) {
      problems.push('SESSION_SECRET must be at least 32 characters (openssl rand -hex 32)')
    }
    if (!config.github.clientId) problems.push('GITHUB_CLIENT_ID is not set')
    if (!config.github.clientSecret) problems.push('GITHUB_CLIENT_SECRET is not set')
    if (!config.publicUrl) problems.push('PUBLIC_URL is not set')
  }
  if (config.publicUrl && !/^https?:\/\//.test(config.publicUrl)) {
    problems.push('PUBLIC_URL must be an absolute http(s) URL')
  }
  return problems
}
