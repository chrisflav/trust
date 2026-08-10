/**
 * The schema, applied on boot.
 *
 * Still idempotent rather than a migration chain, but no longer *only* that:
 * there is a running deployment now, so anything that changes an existing table
 * is an explicit additive step (`migrations`) rather than a hopeful `CREATE
 * TABLE IF NOT EXISTS` that silently does nothing.
 *
 * Tables added for federation store their timestamps as ISO-8601 text in both
 * dialects.  The older tables keep `TIMESTAMPTZ` on Postgres because they exist
 * in a live database and rewriting them would be a migration with nothing to
 * show for it; the read path normalises both.
 */

import type { Db, Dialect } from './db'

interface Types {
  id: string
  bigint: string
  timestamp: string
}

const TYPES: Record<Dialect, Types> = {
  pg: { id: 'BIGSERIAL PRIMARY KEY', bigint: 'BIGINT', timestamp: 'TIMESTAMPTZ' },
  sqlite: { id: 'INTEGER PRIMARY KEY AUTOINCREMENT', bigint: 'INTEGER', timestamp: 'TEXT' },
}

function schema(dialect: Dialect): string {
  const t = TYPES[dialect]
  return `
CREATE TABLE IF NOT EXISTS identity (
  id          ${t.id},
  github_id   ${t.bigint}  NOT NULL UNIQUE,
  login       TEXT         NOT NULL UNIQUE,
  avatar_url  TEXT         NOT NULL DEFAULT '',
  created_at  ${t.timestamp}
);

-- Public keys only.  A private key is never sent here: certificates are signed
-- on the machine that holds the key, and this server only ever checks them.
CREATE TABLE IF NOT EXISTS gpg_key (
  id           ${t.id},
  identity_id  ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  fingerprint  TEXT        NOT NULL,
  armored      TEXT        NOT NULL,
  -- 'github' when the same key is published on the account, 'self' when only
  -- uploaded here.  A reader can weigh the two differently.
  verified_via TEXT        NOT NULL DEFAULT 'self',
  added_at     ${t.timestamp},
  UNIQUE (identity_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS gpg_key_fingerprint ON gpg_key (fingerprint);

CREATE TABLE IF NOT EXISTS certificate (
  id           ${t.id},
  issuer_id    ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  decl         TEXT        NOT NULL,
  decl_hash    TEXT        NOT NULL,
  hasher       TEXT        NOT NULL,
  repo         TEXT        NOT NULL,
  commit_sha   TEXT        NOT NULL,
  toolchain    TEXT        NOT NULL,
  asserted_at  ${t.timestamp} NOT NULL,
  -- The timestamp *as it was signed*, byte for byte.
  --
  -- A signature covers the claim's exact characters, and re-rendering a parsed
  -- timestamp does not reproduce them: the Lean CLI writes second precision, and
  -- Date.toISOString hands back milliseconds.  Serving the rendered form makes
  -- every certificate fail to re-verify — silently, and for everyone except the
  -- machine that signed it.  So the column above is for ordering, and this one
  -- is the truth.
  asserted_text TEXT       NOT NULL DEFAULT '',
  note         TEXT        NOT NULL DEFAULT '',
  signature    TEXT,
  fingerprint  TEXT,
  -- A cache of a check the client is expected to repeat, never the authority.
  assurance    TEXT        NOT NULL DEFAULT 'attested',
  revoked_at   ${t.timestamp},
  created_at   ${t.timestamp},
  -- When this row last changed, in epoch milliseconds.  Export is ordered by
  -- it, so it is the thing a peer's cursor walks; a row that changes without
  -- bumping it is a row that never reaches anyone again.
  updated_ms   ${t.bigint}  NOT NULL DEFAULT 0,
  -- One live assertion per person per hash; re-issuing replaces it.
  UNIQUE (issuer_id, decl_hash, hasher)
);

-- The hot path: "who trusts this declaration".
CREATE INDEX IF NOT EXISTS certificate_lookup ON certificate (decl_hash, hasher);
CREATE INDEX IF NOT EXISTS certificate_export ON certificate (updated_ms, id);

-- Tokens for the command line, which cannot hold a browser cookie session.
-- Only the hash is stored: a leaked database should not hand anyone the ability
-- to publish as someone else.  A token says who is publishing; it is not what
-- makes a certificate trustworthy, since it cannot forge a signature.
CREATE TABLE IF NOT EXISTS api_token (
  id           ${t.id},
  identity_id  ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  token_sha256 TEXT        NOT NULL UNIQUE,
  name         TEXT        NOT NULL DEFAULT '',
  created_at   ${t.timestamp},
  last_used_at ${t.timestamp}
);

-- Whose certificates count for you.  Explicit and non-transitive: trusting
-- someone does not silently enrol everyone they trust.
CREATE TABLE IF NOT EXISTS trust_list (
  truster_id  ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  trusted_id  ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  added_at    ${t.timestamp},
  PRIMARY KEY (truster_id, trusted_id)
);

-- The portable half of the same idea.  A login only means something on the
-- server that issued it; a fingerprint means the same thing everywhere, so
-- following one is what survives a certificate arriving from another node.
CREATE TABLE IF NOT EXISTS trust_key (
  truster_id  ${t.bigint} NOT NULL REFERENCES identity(id) ON DELETE CASCADE,
  fingerprint TEXT        NOT NULL,
  label       TEXT        NOT NULL DEFAULT '',
  added_at    TEXT        NOT NULL DEFAULT '',
  PRIMARY KEY (truster_id, fingerprint)
);

-- Certificates signed elsewhere, verified here before they were stored.  Kept
-- apart from the certificate table because the two say different things: a
-- local row may be attested on this server's word, and one of these is always
-- a checked signature or it would not be here at all.
CREATE TABLE IF NOT EXISTS remote_certificate (
  id            ${t.id},
  fingerprint   TEXT NOT NULL,
  decl          TEXT NOT NULL,
  decl_hash     TEXT NOT NULL,
  hasher        TEXT NOT NULL,
  repo          TEXT NOT NULL,
  commit_sha    TEXT NOT NULL,
  toolchain     TEXT NOT NULL,
  -- Verbatim, for the same reason as certificate.asserted_text; the integer
  -- beside it is what comparisons and ordering use, so that neither depends on
  -- how a remote node happened to spell its timestamp.
  asserted_at   TEXT NOT NULL,
  asserted_ms   ${t.bigint} NOT NULL DEFAULT 0,
  note          TEXT NOT NULL DEFAULT '',
  signature     TEXT NOT NULL,
  armored_key   TEXT NOT NULL,
  -- Unverifiable, carried for display, never allowed to affect a decision.
  hint_issuer   TEXT NOT NULL DEFAULT '',
  hint_key_via  TEXT NOT NULL DEFAULT '',
  origin        TEXT NOT NULL DEFAULT '',
  from_peer     TEXT NOT NULL DEFAULT '',
  fetched_ms    ${t.bigint} NOT NULL DEFAULT 0,
  updated_ms    ${t.bigint} NOT NULL DEFAULT 0,
  UNIQUE (fingerprint, decl_hash, hasher)
);

CREATE INDEX IF NOT EXISTS remote_certificate_lookup ON remote_certificate (decl_hash, hasher);
CREATE INDEX IF NOT EXISTS remote_certificate_signer ON remote_certificate (fingerprint);

-- Withdrawals, signed by the key that made the assertion.  Stored even when
-- the certificate they withdraw has not been seen: it may arrive later by
-- another path, and a race there would resolve in favour of the assertion.
CREATE TABLE IF NOT EXISTS revocation (
  id          ${t.id},
  fingerprint TEXT NOT NULL,
  decl_hash   TEXT NOT NULL,
  hasher      TEXT NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  revoked_at  TEXT NOT NULL,
  revoked_ms  ${t.bigint} NOT NULL DEFAULT 0,
  signature   TEXT NOT NULL,
  armored_key TEXT NOT NULL,
  updated_ms  ${t.bigint} NOT NULL DEFAULT 0,
  UNIQUE (fingerprint, decl_hash, hasher)
);

CREATE INDEX IF NOT EXISTS revocation_lookup ON revocation (decl_hash, hasher);
CREATE INDEX IF NOT EXISTS revocation_export ON revocation (updated_ms, id);

-- Other nodes.  The status column is the operator's judgement: discovery may
-- only ever propose a candidate, never promote one.
CREATE TABLE IF NOT EXISTS peer (
  id           ${t.id},
  url          TEXT NOT NULL UNIQUE,
  name         TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'candidate',
  cursor       TEXT NOT NULL DEFAULT '',
  last_seen_ms ${t.bigint} NOT NULL DEFAULT 0,
  last_error   TEXT NOT NULL DEFAULT '',
  added_ms     ${t.bigint} NOT NULL DEFAULT 0
);
`
}

/**
 * Changes to tables that already exist somewhere.
 *
 * Only Postgres needs these: a SQLite database is always created from the
 * current schema above, because a local one is a file somebody made this week.
 * `ADD COLUMN IF NOT EXISTS` makes each step safe to re-run, which is what lets
 * this stay a list rather than become a version table.
 */
const MIGRATIONS: Record<Dialect, string[]> = {
  pg: [
    `ALTER TABLE certificate ADD COLUMN IF NOT EXISTS updated_ms BIGINT NOT NULL DEFAULT 0`,
    // Rows written before there was an export cursor would otherwise sort at
    // zero forever, which is harmless but means every peer re-reads them on
    // every first sync.  Their creation time is the honest answer.
    `UPDATE certificate SET updated_ms = CAST(EXTRACT(EPOCH FROM COALESCE(created_at, now())) * 1000 AS BIGINT)
      WHERE updated_ms = 0`,
    `ALTER TABLE certificate ADD COLUMN IF NOT EXISTS asserted_text TEXT NOT NULL DEFAULT ''`,
    // The exact bytes of an older row's timestamp were never stored, so they
    // cannot be recovered.  Second precision is what every signer this server
    // has seen produces, so it is the best reconstruction available — and a
    // wrong guess here fails visibly, as a signature that will not verify,
    // rather than quietly.
    `UPDATE certificate
        SET asserted_text = to_char(asserted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
      WHERE asserted_text = ''`,
  ],
  sqlite: [],
}

export async function migrate(db: Db): Promise<void> {
  await db.exec(schema(db.dialect))
  for (const step of MIGRATIONS[db.dialect]) await db.exec(step)
}
