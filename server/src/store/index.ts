/**
 * Every query this server makes, written once against both dialects.
 *
 * The rules that keep it portable are stated in `db.ts`: no `now()`, no `::`
 * casts, conditions built here rather than smuggled into SQL as null guards.
 * The cost is that this file is a little more verbose than a Postgres-only one
 * would be; the benefit is that a local database and a public one run the same
 * code, which is the whole premise of the thing.
 */

import type { Claim, Revocation } from '../certificate'
import type { Entry, RevocationEntry } from '../federation/protocol'
import { encodeCursor, type Bundle } from '../federation/protocol'
import { migrate } from './schema'
import type { Db } from './db'

export interface SessionUser {
  id: number
  login: string
}

export interface LocalCertificate {
  issuer: string
  avatarUrl: string
  claim: Claim
  signature: string | null
  fingerprint: string | null
  assurance: 'signed' | 'attested'
  keyVerifiedVia: string | null
  armoredKey: string | null
  updatedMs: number
  id: number
}

export interface RemoteCertificate {
  claim: Claim
  signature: string
  armoredKey: string
  fingerprint: string
  hints: { issuer?: string; keyVerifiedVia?: string; origin?: string }
  fromPeer: string
  fetchedMs: number
  updatedMs: number
  id: number
}

export interface StoredRevocation {
  revocation: Revocation
  signature: string
  armoredKey: string
  updatedMs: number
  id: number
}

export type PeerStatus = 'seed' | 'active' | 'candidate' | 'blocked'

export interface Peer {
  id: number
  url: string
  name: string
  status: PeerStatus
  cursor: string
  lastSeenMs: number
  lastError: string
}

export interface CertificateQuery {
  hash?: string
  hasher?: string
  fingerprint?: string
  limit?: number
}

/** Both dialects hand back timestamps their own way; callers want one way. */
function iso(value: unknown): string {
  if (value instanceof Date) return value.toISOString()
  if (typeof value === 'string' && value.length > 0) {
    const parsed = Date.parse(value)
    return Number.isNaN(parsed) ? value : new Date(parsed).toISOString()
  }
  if (typeof value === 'number') return new Date(value).toISOString()
  return ''
}

function int(value: unknown): number {
  if (typeof value === 'number') return value
  if (typeof value === 'bigint') return Number(value)
  if (typeof value === 'string') return Number(value)
  return 0
}

export class Store {
  constructor(private readonly db: Db) {}

  get dialect(): string {
    return this.db.dialect
  }

  async ready(): Promise<void> {
    await migrate(this.db)
  }

  async health(): Promise<void> {
    await this.db.query('SELECT 1 AS ok')
  }

  async close(): Promise<void> {
    await this.db.close()
  }

  // ---------------------------------------------------------- identities --

  async upsertIdentity(user: {
    githubId: number
    login: string
    avatarUrl: string
  }): Promise<SessionUser> {
    const rows = await this.db.query<{ id: unknown; login: string }>(
      `INSERT INTO identity (github_id, login, avatar_url, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (github_id) DO UPDATE SET login = EXCLUDED.login, avatar_url = EXCLUDED.avatar_url
       RETURNING id, login`,
      [user.githubId, user.login, user.avatarUrl, new Date().toISOString()],
    )
    return { id: int(rows[0].id), login: rows[0].login }
  }

  async identityByLogin(login: string): Promise<SessionUser | null> {
    const rows = await this.db.query<{ id: unknown; login: string }>(
      'SELECT id, login FROM identity WHERE login = $1',
      [login],
    )
    return rows.length > 0 ? { id: int(rows[0].id), login: rows[0].login } : null
  }

  /**
   * The single identity a local database has.
   *
   * Local mode has no OAuth and nobody to authenticate against, so the identity
   * exists to hang keys and a trust list off — not to establish who anyone is.
   * The negative `github_id` keeps it from ever colliding with a real one.
   */
  async ensureLocalIdentity(login: string): Promise<SessionUser> {
    const existing = await this.identityByLogin(login)
    if (existing) return existing
    return this.upsertIdentity({ githubId: -1, login, avatarUrl: '' })
  }

  // -------------------------------------------------------------- tokens --

  async createToken(identityId: number, tokenSha256: string, name: string): Promise<void> {
    await this.db.query(
      'INSERT INTO api_token (identity_id, token_sha256, name, created_at) VALUES ($1, $2, $3, $4)',
      [identityId, tokenSha256, name, new Date().toISOString()],
    )
  }

  async listTokens(
    identityId: number,
  ): Promise<{ id: number; name: string; createdAt: string; lastUsedAt: string }[]> {
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT id, name, created_at, last_used_at FROM api_token
        WHERE identity_id = $1 ORDER BY created_at DESC`,
      [identityId],
    )
    return rows.map((row) => ({
      id: int(row.id),
      name: String(row.name ?? ''),
      createdAt: iso(row.created_at),
      lastUsedAt: iso(row.last_used_at),
    }))
  }

  async deleteToken(identityId: number, id: string): Promise<void> {
    await this.db.query('DELETE FROM api_token WHERE id = $1 AND identity_id = $2', [
      Number(id),
      identityId,
    ])
  }

  /**
   * Resolve a bearer token, noting that it was used.
   *
   * Two statements rather than one `UPDATE … FROM … RETURNING`: that form is
   * spelled differently in the two dialects, and the atomicity it would buy is
   * over a "last used" column nobody makes a decision from.
   */
  async identityForToken(tokenSha256: string): Promise<SessionUser | null> {
    const rows = await this.db.query<{ id: unknown; login: string; token_id: unknown }>(
      `SELECT i.id AS id, i.login AS login, t.id AS token_id
         FROM api_token t JOIN identity i ON i.id = t.identity_id
        WHERE t.token_sha256 = $1`,
      [tokenSha256],
    )
    if (rows.length === 0) return null
    await this.db.query('UPDATE api_token SET last_used_at = $1 WHERE id = $2', [
      new Date().toISOString(),
      int(rows[0].token_id),
    ])
    return { id: int(rows[0].id), login: rows[0].login }
  }

  // ---------------------------------------------------------------- keys --

  async upsertKey(
    identityId: number,
    fingerprint: string,
    armored: string,
    verifiedVia: string,
  ): Promise<void> {
    await this.db.query(
      `INSERT INTO gpg_key (identity_id, fingerprint, armored, verified_via, added_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (identity_id, fingerprint) DO UPDATE
         SET armored = EXCLUDED.armored, verified_via = EXCLUDED.verified_via`,
      [identityId, fingerprint.toLowerCase(), armored, verifiedVia, new Date().toISOString()],
    )
  }

  async keysForLogin(
    login: string,
  ): Promise<{ fingerprint: string; armored: string; verifiedVia: string }[]> {
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT k.fingerprint, k.armored, k.verified_via
         FROM gpg_key k JOIN identity i ON i.id = k.identity_id
        WHERE i.login = $1`,
      [login],
    )
    return rows.map((row) => ({
      fingerprint: String(row.fingerprint),
      armored: String(row.armored),
      verifiedVia: String(row.verified_via),
    }))
  }

  async keysForIdentity(identityId: number): Promise<string[]> {
    const rows = await this.db.query<{ armored: string }>(
      'SELECT armored FROM gpg_key WHERE identity_id = $1',
      [identityId],
    )
    return rows.map((row) => row.armored)
  }

  /** Any key this node has seen, local or arrived with a federated entry. */
  async keyByFingerprint(
    fingerprint: string,
  ): Promise<{ armored: string; login: string; verifiedVia: string } | null> {
    const local = await this.db.query<Record<string, unknown>>(
      `SELECT k.armored, i.login, k.verified_via
         FROM gpg_key k JOIN identity i ON i.id = k.identity_id
        WHERE k.fingerprint = $1 LIMIT 1`,
      [fingerprint.toLowerCase()],
    )
    if (local.length > 0) {
      return {
        armored: String(local[0].armored),
        login: String(local[0].login),
        verifiedVia: String(local[0].verified_via),
      }
    }
    const remote = await this.db.query<Record<string, unknown>>(
      `SELECT armored_key, hint_issuer FROM remote_certificate WHERE fingerprint = $1 LIMIT 1`,
      [fingerprint.toLowerCase()],
    )
    if (remote.length === 0) return null
    return {
      armored: String(remote[0].armored_key),
      login: String(remote[0].hint_issuer ?? ''),
      // A key that arrived with an entry is tied to nothing this node checked.
      verifiedVia: 'remote',
    }
  }

  // -------------------------------------------------- local certificates --

  async upsertCertificate(row: {
    issuerId: number
    claim: Claim
    signature: string | null
    fingerprint: string | null
    assurance: string
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO certificate
         (issuer_id, decl, decl_hash, hasher, repo, commit_sha, toolchain,
          asserted_at, asserted_text, note, signature, fingerprint, assurance, created_at, updated_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       ON CONFLICT (issuer_id, decl_hash, hasher) DO UPDATE SET
         decl = EXCLUDED.decl, repo = EXCLUDED.repo, commit_sha = EXCLUDED.commit_sha,
         toolchain = EXCLUDED.toolchain, asserted_at = EXCLUDED.asserted_at,
         asserted_text = EXCLUDED.asserted_text,
         note = EXCLUDED.note, signature = EXCLUDED.signature,
         fingerprint = EXCLUDED.fingerprint, assurance = EXCLUDED.assurance,
         updated_ms = EXCLUDED.updated_ms, revoked_at = NULL`,
      [
        row.issuerId,
        row.claim.decl,
        row.claim.hash,
        row.claim.hasher,
        row.claim.repo,
        row.claim.commit,
        row.claim.toolchain,
        row.claim.asserted,
        // The same value twice: once for a column that will parse it, once for
        // the column that must never touch it.
        row.claim.asserted,
        row.claim.note,
        row.signature,
        row.fingerprint ? row.fingerprint.toLowerCase() : null,
        row.assurance,
        new Date().toISOString(),
        Date.now(),
      ],
    )
  }

  private certificateWhere(
    query: CertificateQuery,
    prefix: string,
  ): { clause: string; params: unknown[] } {
    const conditions: string[] = []
    const params: unknown[] = []
    if (query.hash) {
      params.push(query.hash)
      conditions.push(`${prefix}decl_hash = $${params.length}`)
    }
    if (query.hasher) {
      params.push(query.hasher)
      conditions.push(`${prefix}hasher = $${params.length}`)
    }
    if (query.fingerprint) {
      params.push(query.fingerprint.toLowerCase())
      conditions.push(`${prefix}fingerprint = $${params.length}`)
    }
    return { clause: conditions.length > 0 ? `AND ${conditions.join(' AND ')}` : '', params }
  }

  async localCertificates(query: CertificateQuery): Promise<LocalCertificate[]> {
    const { clause, params } = this.certificateWhere(query, 'c.')
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT c.id, i.login, i.avatar_url, c.decl, c.decl_hash, c.hasher, c.repo,
              c.commit_sha, c.toolchain, c.asserted_at, c.asserted_text, c.note, c.signature,
              c.fingerprint, c.assurance, c.updated_ms, k.verified_via, k.armored
         FROM certificate c
         JOIN identity i ON i.id = c.issuer_id
         LEFT JOIN gpg_key k ON k.identity_id = c.issuer_id AND k.fingerprint = c.fingerprint
        WHERE c.revoked_at IS NULL ${clause}
        ORDER BY c.asserted_at DESC`,
      params,
    )
    return rows.map((row) => this.toLocalCertificate(row))
  }

  private toLocalCertificate(row: Record<string, unknown>): LocalCertificate {
    return {
      id: int(row.id),
      issuer: String(row.login ?? ''),
      avatarUrl: String(row.avatar_url ?? ''),
      claim: {
        decl: String(row.decl ?? ''),
        hash: String(row.decl_hash ?? ''),
        hasher: String(row.hasher ?? ''),
        repo: String(row.repo ?? ''),
        commit: String(row.commit_sha ?? ''),
        toolchain: String(row.toolchain ?? ''),
        // Verbatim when it was stored that way.  The fallback is for rows
        // written before that column existed, whose exact bytes are gone.
        asserted: row.asserted_text ? String(row.asserted_text) : iso(row.asserted_at),
        note: String(row.note ?? ''),
      },
      signature: row.signature ? String(row.signature) : null,
      fingerprint: row.fingerprint ? String(row.fingerprint) : null,
      assurance: row.assurance === 'signed' ? 'signed' : 'attested',
      keyVerifiedVia: row.verified_via ? String(row.verified_via) : null,
      armoredKey: row.armored ? String(row.armored) : null,
      updatedMs: int(row.updated_ms),
    }
  }

  /** Mark a local certificate withdrawn.  Federation needs §6's signed form. */
  async revokeLocal(issuerId: number, hash: string): Promise<void> {
    const now = new Date().toISOString()
    await this.db.query(
      'UPDATE certificate SET revoked_at = $1, updated_ms = $2 WHERE issuer_id = $3 AND decl_hash = $4',
      [now, Date.now(), issuerId, hash],
    )
  }

  // ------------------------------------------------- remote certificates --

  async upsertRemote(entry: Entry, fromPeer: string, fetchedMs: number): Promise<void> {
    await this.db.query(
      `INSERT INTO remote_certificate
         (fingerprint, decl, decl_hash, hasher, repo, commit_sha, toolchain, asserted_at,
          asserted_ms, note, signature, armored_key, hint_issuer, hint_key_via, origin,
          from_peer, fetched_ms, updated_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       ON CONFLICT (fingerprint, decl_hash, hasher) DO UPDATE SET
         decl = EXCLUDED.decl, repo = EXCLUDED.repo, commit_sha = EXCLUDED.commit_sha,
         toolchain = EXCLUDED.toolchain, note = EXCLUDED.note,
         signature = EXCLUDED.signature, armored_key = EXCLUDED.armored_key,
         hint_issuer = EXCLUDED.hint_issuer, hint_key_via = EXCLUDED.hint_key_via,
         origin = EXCLUDED.origin, from_peer = EXCLUDED.from_peer,
         fetched_ms = EXCLUDED.fetched_ms, asserted_at = EXCLUDED.asserted_at,
         asserted_ms = EXCLUDED.asserted_ms, updated_ms = EXCLUDED.updated_ms
       WHERE EXCLUDED.asserted_ms > remote_certificate.asserted_ms`,
      [
        entry.fingerprint,
        entry.claim.decl,
        entry.claim.hash,
        entry.claim.hasher,
        entry.claim.repo,
        entry.claim.commit,
        entry.claim.toolchain,
        entry.claim.asserted,
        Date.parse(entry.claim.asserted),
        entry.claim.note,
        entry.signature,
        entry.key,
        entry.hints?.issuer ?? '',
        entry.hints?.keyVerifiedVia ?? '',
        entry.hints?.origin ?? '',
        fromPeer,
        fetchedMs,
        Date.now(),
      ],
    )
  }

  async remoteCertificates(query: CertificateQuery): Promise<RemoteCertificate[]> {
    const { clause, params } = this.certificateWhere(query, '')
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT * FROM remote_certificate WHERE 1 = 1 ${clause} ORDER BY asserted_ms DESC`,
      params,
    )
    return rows.map((row) => this.toRemoteCertificate(row))
  }

  private toRemoteCertificate(row: Record<string, unknown>): RemoteCertificate {
    const hints: RemoteCertificate['hints'] = {}
    if (row.hint_issuer) hints.issuer = String(row.hint_issuer)
    if (row.hint_key_via) hints.keyVerifiedVia = String(row.hint_key_via)
    if (row.origin) hints.origin = String(row.origin)
    return {
      id: int(row.id),
      claim: {
        decl: String(row.decl ?? ''),
        hash: String(row.decl_hash ?? ''),
        hasher: String(row.hasher ?? ''),
        repo: String(row.repo ?? ''),
        commit: String(row.commit_sha ?? ''),
        toolchain: String(row.toolchain ?? ''),
        // Never normalised: these bytes are what a signature covers, and this
        // node did not write them.
        asserted: String(row.asserted_at ?? ''),
        note: String(row.note ?? ''),
      },
      signature: String(row.signature ?? ''),
      armoredKey: String(row.armored_key ?? ''),
      fingerprint: String(row.fingerprint ?? ''),
      hints,
      fromPeer: String(row.from_peer ?? ''),
      fetchedMs: int(row.fetched_ms),
      updatedMs: int(row.updated_ms),
    }
  }

  /**
   * The most recent time anything was cached for this question.
   *
   * A fan-out is skipped when this is inside the TTL.  "Nothing cached" and
   * "cached, and the answer was nothing" are indistinguishable here, so a
   * question nobody has answered is asked again every time — which is the
   * conservative way round.
   */
  async remoteFreshness(query: CertificateQuery): Promise<number> {
    const { clause, params } = this.certificateWhere(query, '')
    const rows = await this.db.query<{ newest: unknown }>(
      `SELECT MAX(fetched_ms) AS newest FROM remote_certificate WHERE 1 = 1 ${clause}`,
      params,
    )
    return rows.length > 0 ? int(rows[0].newest) : 0
  }

  // --------------------------------------------------------- revocations --

  async upsertRevocation(entry: RevocationEntry): Promise<void> {
    await this.db.query(
      `INSERT INTO revocation
         (fingerprint, decl_hash, hasher, reason, revoked_at, revoked_ms,
          signature, armored_key, updated_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (fingerprint, decl_hash, hasher) DO UPDATE SET
         reason = EXCLUDED.reason, revoked_at = EXCLUDED.revoked_at,
         revoked_ms = EXCLUDED.revoked_ms,
         signature = EXCLUDED.signature, armored_key = EXCLUDED.armored_key,
         updated_ms = EXCLUDED.updated_ms
       WHERE EXCLUDED.revoked_ms > revocation.revoked_ms`,
      [
        entry.revocation.fingerprint,
        entry.revocation.hash,
        entry.revocation.hasher,
        entry.revocation.reason,
        entry.revocation.revoked,
        Date.parse(entry.revocation.revoked),
        entry.signature,
        entry.key,
        Date.now(),
      ],
    )
  }

  async revocations(query: CertificateQuery): Promise<StoredRevocation[]> {
    const { clause, params } = this.certificateWhere(query, '')
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT * FROM revocation WHERE 1 = 1 ${clause}`,
      params,
    )
    return rows.map((row) => this.toRevocation(row))
  }

  private toRevocation(row: Record<string, unknown>): StoredRevocation {
    return {
      id: int(row.id),
      revocation: {
        fingerprint: String(row.fingerprint ?? ''),
        hash: String(row.decl_hash ?? ''),
        hasher: String(row.hasher ?? ''),
        reason: String(row.reason ?? ''),
        revoked: String(row.revoked_at ?? ''),
      },
      signature: String(row.signature ?? ''),
      armoredKey: String(row.armored_key ?? ''),
      updatedMs: int(row.updated_ms),
    }
  }

  // -------------------------------------------------------------- export --

  /**
   * Signed local certificates, in cursor order, for a peer catching up.
   *
   * `attested` rows are excluded in the query rather than filtered afterwards:
   * §3.1 says they do not federate, and a limit applied before the filter would
   * silently shrink pages to nothing on a node where most rows are attested.
   */
  async exportCertificates(
    after: { ms: number; id: number } | null,
    limit: number,
  ): Promise<{ certificates: LocalCertificate[]; cursor: string; complete: boolean }> {
    const params: unknown[] = []
    let clause = ''
    if (after) {
      params.push(after.ms, after.id)
      clause = 'AND (c.updated_ms > $1 OR (c.updated_ms = $1 AND c.id > $2))'
    }
    params.push(limit + 1)
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT c.id, i.login, i.avatar_url, c.decl, c.decl_hash, c.hasher, c.repo,
              c.commit_sha, c.toolchain, c.asserted_at, c.asserted_text, c.note, c.signature,
              c.fingerprint, c.assurance, c.updated_ms, k.verified_via, k.armored
         FROM certificate c
         JOIN identity i ON i.id = c.issuer_id
         LEFT JOIN gpg_key k ON k.identity_id = c.issuer_id AND k.fingerprint = c.fingerprint
        WHERE c.revoked_at IS NULL AND c.assurance = 'signed'
          AND c.signature IS NOT NULL AND k.armored IS NOT NULL ${clause}
        ORDER BY c.updated_ms, c.id
        LIMIT $${params.length}`,
      params,
    )
    const complete = rows.length <= limit
    const page = rows.slice(0, limit).map((row) => this.toLocalCertificate(row))
    const last = page[page.length - 1]
    return {
      certificates: page,
      // With nothing new, the cursor the caller sent is returned unchanged, so
      // that an idle peer does not walk backwards to the beginning.
      cursor: last
        ? encodeCursor(last.updatedMs, last.id)
        : after
          ? encodeCursor(after.ms, after.id)
          : '',
      complete,
    }
  }

  async exportRevocations(
    after: { ms: number; id: number } | null,
    limit: number,
  ): Promise<StoredRevocation[]> {
    const params: unknown[] = []
    let clause = ''
    if (after) {
      params.push(after.ms, after.id)
      clause = 'AND (updated_ms > $1 OR (updated_ms = $1 AND id > $2))'
    }
    params.push(limit)
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT * FROM revocation WHERE 1 = 1 ${clause} ORDER BY updated_ms, id LIMIT $${params.length}`,
      params,
    )
    return rows.map((row) => this.toRevocation(row))
  }

  // ---------------------------------------------------------- trust list --

  async followLogin(trusterId: number, login: string): Promise<boolean> {
    const target = await this.identityByLogin(login)
    if (!target) return false
    await this.db.query(
      `INSERT INTO trust_list (truster_id, trusted_id, added_at) VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [trusterId, target.id, new Date().toISOString()],
    )
    return true
  }

  async unfollowLogin(trusterId: number, login: string): Promise<void> {
    await this.db.query(
      `DELETE FROM trust_list WHERE truster_id = $1
        AND trusted_id = (SELECT id FROM identity WHERE login = $2)`,
      [trusterId, login],
    )
  }

  async listFollows(trusterId: number): Promise<{ login: string; avatarUrl: string }[]> {
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT i.login, i.avatar_url FROM trust_list t JOIN identity i ON i.id = t.trusted_id
        WHERE t.truster_id = $1 ORDER BY i.login`,
      [trusterId],
    )
    return rows.map((row) => ({
      login: String(row.login),
      avatarUrl: String(row.avatar_url ?? ''),
    }))
  }

  async followKey(trusterId: number, fingerprint: string, label: string): Promise<void> {
    await this.db.query(
      `INSERT INTO trust_key (truster_id, fingerprint, label, added_at) VALUES ($1, $2, $3, $4)
       ON CONFLICT (truster_id, fingerprint) DO UPDATE SET label = EXCLUDED.label`,
      [trusterId, fingerprint.toLowerCase(), label, new Date().toISOString()],
    )
  }

  async unfollowKey(trusterId: number, fingerprint: string): Promise<void> {
    await this.db.query('DELETE FROM trust_key WHERE truster_id = $1 AND fingerprint = $2', [
      trusterId,
      fingerprint.toLowerCase(),
    ])
  }

  async listKeyFollows(trusterId: number): Promise<{ fingerprint: string; label: string }[]> {
    const rows = await this.db.query<Record<string, unknown>>(
      'SELECT fingerprint, label FROM trust_key WHERE truster_id = $1 ORDER BY fingerprint',
      [trusterId],
    )
    return rows.map((row) => ({
      fingerprint: String(row.fingerprint),
      label: String(row.label ?? ''),
    }))
  }

  /**
   * Everything the people and keys you follow vouch for.
   *
   * Two sources, one flat set: local rows reached through a login you follow,
   * and any row — local or federated — signed by a key you follow.  The second
   * is what makes a trust list portable, since a login is only meaningful on
   * the server that issued it.
   *
   * Still one hop.  Following someone never enrols the people *they* follow,
   * and federation does not change that: it widens who you can hear from, not
   * whom you trust.
   */
  async trustedHashes(
    trusterId: number,
    hasher?: string,
  ): Promise<{ hash: string; hasher: string; fingerprint: string; asserted: string }[]> {
    const params: unknown[] = [trusterId]
    let hasherClause = ''
    if (hasher) {
      params.push(hasher)
      hasherClause = `AND hasher = $2`
    }
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT decl_hash, hasher, fingerprint, asserted_at FROM (
         SELECT c.decl_hash AS decl_hash, c.hasher AS hasher,
                COALESCE(c.fingerprint, '') AS fingerprint, c.asserted_at AS asserted_at
           FROM certificate c
           JOIN trust_list t ON t.trusted_id = c.issuer_id
          WHERE t.truster_id = $1 AND c.revoked_at IS NULL
         UNION
         SELECT c.decl_hash, c.hasher, COALESCE(c.fingerprint, ''), c.asserted_at
           FROM certificate c
           JOIN trust_key k ON k.fingerprint = c.fingerprint
          WHERE k.truster_id = $1 AND c.revoked_at IS NULL
         UNION
         SELECT r.decl_hash, r.hasher, r.fingerprint, r.asserted_at
           FROM remote_certificate r
           JOIN trust_key k ON k.fingerprint = r.fingerprint
          WHERE k.truster_id = $1
       ) AS trusted
       WHERE 1 = 1 ${hasherClause}`,
      params,
    )
    return rows.map((row) => ({
      hash: String(row.decl_hash),
      hasher: String(row.hasher),
      fingerprint: String(row.fingerprint ?? ''),
      asserted: iso(row.asserted_at),
    }))
  }

  // --------------------------------------------------------------- peers --

  async upsertPeer(url: string, name: string, status: PeerStatus): Promise<void> {
    await this.db.query(
      `INSERT INTO peer (url, name, status, added_ms) VALUES ($1, $2, $3, $4)
       ON CONFLICT (url) DO UPDATE SET name = EXCLUDED.name`,
      [url, name, status, Date.now()],
    )
  }

  async setPeerStatus(url: string, status: PeerStatus): Promise<void> {
    await this.db.query('UPDATE peer SET status = $1 WHERE url = $2', [status, url])
  }

  async peerByUrl(url: string): Promise<Peer | null> {
    const rows = await this.db.query<Record<string, unknown>>('SELECT * FROM peer WHERE url = $1', [
      url,
    ])
    return rows.length > 0 ? this.toPeer(rows[0]) : null
  }

  async listPeers(statuses?: PeerStatus[]): Promise<Peer[]> {
    if (!statuses || statuses.length === 0) {
      const all = await this.db.query<Record<string, unknown>>('SELECT * FROM peer ORDER BY url')
      return all.map((row) => this.toPeer(row))
    }
    const placeholders = statuses.map((_, index) => `$${index + 1}`).join(',')
    const rows = await this.db.query<Record<string, unknown>>(
      `SELECT * FROM peer WHERE status IN (${placeholders}) ORDER BY url`,
      statuses,
    )
    return rows.map((row) => this.toPeer(row))
  }

  async notePeerSeen(url: string, cursor: string, error: string): Promise<void> {
    await this.db.query(
      'UPDATE peer SET last_seen_ms = $1, cursor = $2, last_error = $3 WHERE url = $4',
      [Date.now(), cursor, error, url],
    )
  }

  private toPeer(row: Record<string, unknown>): Peer {
    return {
      id: int(row.id),
      url: String(row.url),
      name: String(row.name ?? ''),
      status: String(row.status ?? 'candidate') as PeerStatus,
      cursor: String(row.cursor ?? ''),
      lastSeenMs: int(row.last_seen_ms),
      lastError: String(row.last_error ?? ''),
    }
  }

  async counts(): Promise<{ certificates: number; peers: number }> {
    const certificates = await this.db.query<{ n: unknown }>(
      `SELECT COUNT(*) AS n FROM certificate WHERE revoked_at IS NULL AND assurance = 'signed'`,
    )
    const peers = await this.db.query<{ n: unknown }>(
      `SELECT COUNT(*) AS n FROM peer WHERE status IN ('seed', 'active')`,
    )
    return { certificates: int(certificates[0]?.n), peers: int(peers[0]?.n) }
  }
}

export type { Bundle }
