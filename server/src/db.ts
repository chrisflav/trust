import { Pool } from 'pg'

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX ?? 10),
})

/**
 * The schema, applied on boot.
 *
 * Idempotent rather than a migration chain: there is one deployment and no
 * released version yet, so a chain would be ceremony.  It becomes worth having
 * the moment someone else runs this.
 */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS identity (
  id          BIGSERIAL PRIMARY KEY,
  github_id   BIGINT      NOT NULL UNIQUE,
  login       TEXT        NOT NULL UNIQUE,
  avatar_url  TEXT        NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Public keys only.  A private key is never sent here: certificates are signed
-- on the machine that holds the key, and this server only ever checks them.
CREATE TABLE IF NOT EXISTS gpg_key (
  id           BIGSERIAL PRIMARY KEY,
  identity_id  BIGINT      NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  fingerprint  TEXT        NOT NULL,
  armored      TEXT        NOT NULL,
  -- 'github' when the same key is published on the account, 'self' when only
  -- uploaded here.  A reader can weigh the two differently.
  verified_via TEXT        NOT NULL DEFAULT 'self',
  added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (identity_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS certificate (
  id           BIGSERIAL PRIMARY KEY,
  issuer_id    BIGINT      NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  decl         TEXT        NOT NULL,
  decl_hash    TEXT        NOT NULL,
  hasher       TEXT        NOT NULL,
  repo         TEXT        NOT NULL,
  commit_sha   TEXT        NOT NULL,
  toolchain    TEXT        NOT NULL,
  asserted_at  TIMESTAMPTZ NOT NULL,
  note         TEXT        NOT NULL DEFAULT '',
  signature    TEXT,
  fingerprint  TEXT,
  -- A cache of a check the client is expected to repeat, never the authority.
  assurance    TEXT        NOT NULL DEFAULT 'attested',
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- One live assertion per person per hash; re-issuing replaces it.
  UNIQUE (issuer_id, decl_hash, hasher)
);

-- The hot path: "who trusts this declaration".
CREATE INDEX IF NOT EXISTS certificate_lookup ON certificate (decl_hash, hasher);

-- Whose certificates count for you.  Explicit and non-transitive: trusting
-- someone does not silently enrol everyone they trust.
CREATE TABLE IF NOT EXISTS trust_list (
  truster_id  BIGINT      NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  trusted_id  BIGINT      NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (truster_id, trusted_id)
);
`

export async function migrate(): Promise<void> {
  await pool.query(SCHEMA)
}

/** Wait for Postgres to accept connections; compose starts us alongside it. */
export async function waitForDatabase(attempts = 30): Promise<void> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await pool.query('SELECT 1')
      return
    } catch (error) {
      if (attempt === attempts) throw error
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
  }
}
