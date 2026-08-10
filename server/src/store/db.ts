/**
 * The two databases this server runs on, behind one very small interface.
 *
 * A public node wants Postgres.  A person keeping their own trust database on
 * their laptop wants a file, and asking them to run Postgres for it would
 * defeat the point — a local database and a public one are supposed to differ
 * in deployment, not in kind.
 *
 * What is deliberately *not* here is two sets of queries.  The dialects differ
 * in placeholder syntax and in a handful of column types, and nothing else that
 * this schema uses, so the SQL is written once (`store/index.ts`) against the
 * common subset and the differences are confined to this file and to
 * `schema.ts`.  Two hand-written stores would drift, and the one that drifted
 * would be the one nobody runs in production.
 *
 * Two rules keep the common subset honest:
 *
 *   * no `now()` — timestamps are passed in from JavaScript, so both dialects
 *     store exactly the same bytes and comparisons cannot depend on the server's
 *     idea of a clock or a time zone;
 *   * no `::` casts — conditions are built up in TypeScript instead of hidden
 *     behind `$2::text IS NULL OR …`, which is clearer anyway.
 */

export type Dialect = 'pg' | 'sqlite'

export interface Db {
  dialect: Dialect
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>
  exec(sql: string): Promise<void>
  close(): Promise<void>
}

// -------------------------------------------------------------- postgres --

export async function openPostgres(connectionString: string, poolMax = 10): Promise<Db> {
  const { Pool } = await import('pg')
  const pool = new Pool({ connectionString, max: poolMax })
  return {
    dialect: 'pg',
    async query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
      const result = await pool.query(sql, params as unknown[])
      return result.rows as T[]
    },
    async exec(sql: string): Promise<void> {
      await pool.query(sql)
    },
    async close(): Promise<void> {
      await pool.end()
    },
  }
}

/** Wait for Postgres to accept connections; compose starts us alongside it. */
export async function waitForDatabase(db: Db, attempts = 30): Promise<void> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await db.query('SELECT 1')
      return
    } catch (error) {
      if (attempt === attempts) throw error
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
  }
}

// ---------------------------------------------------------------- sqlite --

/**
 * `node:sqlite`, rather than a native module.
 *
 * `better-sqlite3` would mean a compiler and node-gyp in an Alpine image whose
 * whole point is to carry neither, and a build step on every laptop that wants
 * a local database.  The built-in module is marked experimental in Node 22 and
 * prints a warning to that effect; it is stable in 24, and the API used here —
 * `prepare`, `all`, `run` — is the part least likely to move.
 */
export async function openSqlite(path: string): Promise<Db> {
  const { DatabaseSync } = await import('node:sqlite')
  if (path !== ':memory:') {
    const { mkdir } = await import('node:fs/promises')
    const { dirname } = await import('node:path')
    await mkdir(dirname(path), { recursive: true })
  }
  const db = new DatabaseSync(path)
  // WAL keeps a reader from blocking the writer, which matters as soon as a
  // federation pull runs while somebody is reading the same file.
  if (path !== ':memory:') db.exec('PRAGMA journal_mode = WAL')
  db.exec('PRAGMA foreign_keys = ON')

  /** `$1` is Postgres'; `?1` is SQLite's, and it numbers identically. */
  const translate = (sql: string): string => sql.replace(/\$(\d+)/g, '?$1')

  /** SQLite binds five types and no others; booleans and dates are not among them. */
  const bind = (value: unknown): unknown => {
    if (value === undefined || value === null) return null
    if (typeof value === 'boolean') return value ? 1 : 0
    if (value instanceof Date) return value.toISOString()
    return value
  }

  return {
    dialect: 'sqlite',
    async query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
      const statement = db.prepare(translate(sql))
      const bound = params.map(bind)
      // `all` throws on a statement that returns nothing in some versions, so
      // writes go through `run`; RETURNING makes a write a read, hence the test.
      if (/^\s*(select|with)/i.test(sql) || /returning/i.test(sql)) {
        return statement.all(...(bound as never[])) as T[]
      }
      statement.run(...(bound as never[]))
      return []
    },
    async exec(sql: string): Promise<void> {
      db.exec(sql)
    },
    async close(): Promise<void> {
      db.close()
    },
  }
}

export async function openDb(options: {
  kind: Dialect
  connectionString?: string
  path?: string
  poolMax?: number
}): Promise<Db> {
  if (options.kind === 'pg') {
    return openPostgres(options.connectionString ?? '', options.poolMax)
  }
  return openSqlite(options.path ?? ':memory:')
}
