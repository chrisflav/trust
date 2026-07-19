import { Router } from 'express'
import { pool } from './db'
import {
  consumeState,
  currentUser,
  exchangeCode,
  githubPublicKeys,
  issueSession,
  hashToken,
  newState,
  newToken,
  readSession,
  requireUser,
  upsertIdentity,
} from './auth'
import { canonicalClaim, parseClaim, verifySignature, type Claim } from './certificate'

export const routes = Router()

routes.get('/api/health', async (_request, response) => {
  await pool.query('SELECT 1')
  response.json({ ok: true })
})

// ---------------------------------------------------------------- identity --

routes.get('/auth/github', (_request, response) => {
  const redirect = new URL('https://github.com/login/oauth/authorize')
  redirect.searchParams.set('client_id', process.env.GITHUB_CLIENT_ID ?? '')
  redirect.searchParams.set('redirect_uri', `${process.env.PUBLIC_URL}/auth/github/callback`)
  redirect.searchParams.set('scope', 'read:user')
  redirect.searchParams.set('state', newState())
  response.redirect(redirect.toString())
})

routes.get('/auth/github/callback', async (request, response) => {
  const { code, state } = request.query as { code?: string; state?: string }
  if (!code || !state || !consumeState(state)) {
    response.status(400).json({ error: 'bad OAuth state' })
    return
  }
  try {
    const user = await upsertIdentity(await exchangeCode(code))
    issueSession(response, user)
    response.redirect(process.env.APP_URL ?? '/')
  } catch (error) {
    response.status(502).json({ error: String(error instanceof Error ? error.message : error) })
  }
})

routes.get('/api/me', (request, response) => {
  response.json({ user: readSession(request) })
})

routes.post('/auth/logout', (_request, response) => {
  response.clearCookie('trust_session').json({ ok: true })
})

// ------------------------------------------------------------------ tokens --

/**
 * Mint a token for the command line.  Shown once and never again — only its
 * hash is kept, so the server cannot hand it back even to its owner.
 */
routes.post('/api/tokens', requireUser, async (request, response) => {
  const { name } = request.body as { name?: string }
  const token = newToken()
  await pool.query(
    'INSERT INTO api_token (identity_id, token_sha256, name) VALUES ($1, $2, $3)',
    [currentUser(request).id, hashToken(token), typeof name === 'string' ? name.slice(0, 100) : ''],
  )
  response.json({ token, note: 'copy this now; it is not stored and cannot be shown again' })
})

routes.get('/api/tokens', requireUser, async (request, response) => {
  const { rows } = await pool.query(
    `SELECT id, name, created_at AS "createdAt", last_used_at AS "lastUsedAt"
       FROM api_token WHERE identity_id = $1 ORDER BY created_at DESC`,
    [currentUser(request).id],
  )
  response.json({ tokens: rows })
})

routes.delete('/api/tokens/:id', requireUser, async (request, response) => {
  await pool.query('DELETE FROM api_token WHERE id = $1 AND identity_id = $2', [
    request.params.id, currentUser(request).id,
  ])
  response.json({ ok: true })
})

// -------------------------------------------------------------- public keys --

/**
 * Register a public key.
 *
 * Public half only, and the route rejects anything that looks like a private
 * key rather than storing it: a server that never holds signing material
 * cannot leak it, and signing belongs on the machine that holds the key.
 */
routes.post('/api/keys', requireUser, async (request, response) => {
  const { armored } = request.body as { armored?: string }
  if (typeof armored !== 'string' || !armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    response.status(400).json({ error: 'expected an armored PGP *public* key' })
    return
  }
  if (armored.includes('PRIVATE KEY BLOCK')) {
    response.status(400).json({ error: 'that is a private key — never send one here' })
    return
  }
  const user = currentUser(request)
  const openpgp = await import('openpgp')
  let fingerprint: string
  try {
    fingerprint = (await openpgp.readKey({ armoredKey: armored })).getFingerprint()
  } catch (error) {
    response.status(400).json({ error: `unreadable key: ${String(error)}` })
    return
  }
  const published = await githubPublicKeys(user.login)
  const onGitHub = published.some((key) => key.replace(/\s/g, '') === armored.replace(/\s/g, ''))
  await pool.query(
    `INSERT INTO gpg_key (identity_id, fingerprint, armored, verified_via)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (identity_id, fingerprint) DO UPDATE
       SET armored = EXCLUDED.armored, verified_via = EXCLUDED.verified_via`,
    [user.id, fingerprint, armored, onGitHub ? 'github' : 'self'],
  )
  response.json({ fingerprint, verifiedVia: onGitHub ? 'github' : 'self' })
})

routes.get('/api/keys/:login', async (request, response) => {
  const { rows } = await pool.query(
    `SELECT k.fingerprint, k.armored, k.verified_via AS "verifiedVia"
       FROM gpg_key k JOIN identity i ON i.id = k.identity_id
      WHERE i.login = $1`,
    [request.params.login],
  )
  response.json({ keys: rows })
})

// ------------------------------------------------------------- certificates --

async function keysFor(identityId: number): Promise<string[]> {
  const { rows } = await pool.query<{ armored: string }>(
    'SELECT armored FROM gpg_key WHERE identity_id = $1',
    [identityId],
  )
  return rows.map((row) => row.armored)
}

/**
 * Publish a certificate.
 *
 * A signature is optional but is the whole point: unsigned, the row is only
 * this server's word that a logged-in account said something, and is marked
 * `attested` so a reader can tell the difference.
 */
routes.post('/api/certificates', requireUser, async (request, response) => {
  const body = request.body as { claim?: unknown; signature?: string }
  const claim = parseClaim(body.claim)
  if ('error' in claim) {
    response.status(400).json({ error: claim.error })
    return
  }
  const user = currentUser(request)
  let assurance = 'attested'
  let fingerprint: string | null = null
  if (typeof body.signature === 'string' && body.signature.length > 0) {
    const verdict = await verifySignature(claim, body.signature, await keysFor(user.id))
    if (!verdict.ok) {
      response.status(400).json({ error: `signature did not verify: ${verdict.reason}` })
      return
    }
    assurance = 'signed'
    fingerprint = verdict.fingerprint ?? null
  }
  await pool.query(
    `INSERT INTO certificate
       (issuer_id, decl, decl_hash, hasher, repo, commit_sha, toolchain,
        asserted_at, note, signature, fingerprint, assurance)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     ON CONFLICT (issuer_id, decl_hash, hasher) DO UPDATE SET
       decl = EXCLUDED.decl, repo = EXCLUDED.repo, commit_sha = EXCLUDED.commit_sha,
       toolchain = EXCLUDED.toolchain, asserted_at = EXCLUDED.asserted_at,
       note = EXCLUDED.note, signature = EXCLUDED.signature,
       fingerprint = EXCLUDED.fingerprint, assurance = EXCLUDED.assurance,
       revoked_at = NULL`,
    [
      user.id, claim.decl, claim.hash, claim.hasher, claim.repo, claim.commit,
      claim.toolchain, claim.asserted, claim.note, body.signature ?? null, fingerprint, assurance,
    ],
  )
  response.json({ ok: true, assurance })
})

routes.delete('/api/certificates/:hash', requireUser, async (request, response) => {
  await pool.query(
    'UPDATE certificate SET revoked_at = now() WHERE issuer_id = $1 AND decl_hash = $2',
    [currentUser(request).id, request.params.hash],
  )
  response.json({ ok: true })
})

/**
 * Who vouches for this declaration.
 *
 * Returns the canonical claim bytes and the signature alongside the verdict, so
 * a client can repeat the check rather than take this server's word for it.
 */
routes.get('/api/certificates', async (request, response) => {
  const { hash, hasher } = request.query as { hash?: string; hasher?: string }
  if (!hash) {
    response.status(400).json({ error: 'hash is required' })
    return
  }
  const { rows } = await pool.query(
    `SELECT i.login AS issuer, i.avatar_url AS "avatarUrl", c.decl, c.decl_hash AS hash,
            c.hasher, c.repo, c.commit_sha AS commit, c.toolchain,
            c.asserted_at AS asserted, c.note, c.signature, c.fingerprint, c.assurance,
            k.verified_via AS "keyVerifiedVia"
       FROM certificate c
       JOIN identity i ON i.id = c.issuer_id
       LEFT JOIN gpg_key k ON k.identity_id = c.issuer_id AND k.fingerprint = c.fingerprint
      WHERE c.decl_hash = $1 AND ($2::text IS NULL OR c.hasher = $2) AND c.revoked_at IS NULL
      ORDER BY c.assurance = 'signed' DESC, c.asserted_at DESC`,
    [hash, hasher ?? null],
  )
  response.json({
    certificates: rows.map((row) => {
      const claim: Claim = {
        decl: row.decl, hash: row.hash, hasher: row.hasher, repo: row.repo,
        commit: row.commit, toolchain: row.toolchain,
        asserted: new Date(row.asserted).toISOString(), note: row.note,
      }
      return { ...row, claim, canonical: canonicalClaim(claim) }
    }),
  })
})

// -------------------------------------------------------------- trust lists --

routes.get('/api/trust-list', requireUser, async (request, response) => {
  const { rows } = await pool.query(
    `SELECT i.login, i.avatar_url AS "avatarUrl"
       FROM trust_list t JOIN identity i ON i.id = t.trusted_id
      WHERE t.truster_id = $1 ORDER BY i.login`,
    [currentUser(request).id],
  )
  response.json({ trusted: rows })
})

routes.post('/api/trust-list/:login', requireUser, async (request, response) => {
  const { rows } = await pool.query<{ id: string }>('SELECT id FROM identity WHERE login = $1', [
    request.params.login,
  ])
  if (rows.length === 0) {
    response.status(404).json({ error: 'nobody here by that name has published anything' })
    return
  }
  await pool.query(
    `INSERT INTO trust_list (truster_id, trusted_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [currentUser(request).id, Number(rows[0].id)],
  )
  response.json({ ok: true })
})

routes.delete('/api/trust-list/:login', requireUser, async (request, response) => {
  await pool.query(
    `DELETE FROM trust_list USING identity
      WHERE trust_list.trusted_id = identity.id
        AND trust_list.truster_id = $1 AND identity.login = $2`,
    [currentUser(request).id, request.params.login],
  )
  response.json({ ok: true })
})

/**
 * Every hash your trust list vouches for.
 *
 * What the frontend actually needs: one flat set it can turn into trusted
 * declarations.  Non-transitive by construction — the join goes one hop, so
 * trusting someone never silently enrols the people they trust.
 */
routes.get('/api/trusted', requireUser, async (request, response) => {
  const { hasher } = request.query as { hasher?: string }
  const { rows } = await pool.query(
    `SELECT DISTINCT c.decl_hash AS hash, c.hasher
       FROM certificate c
       JOIN trust_list t ON t.trusted_id = c.issuer_id
      WHERE t.truster_id = $1 AND c.revoked_at IS NULL
        AND ($2::text IS NULL OR c.hasher = $2)`,
    [currentUser(request).id, hasher ?? null],
  )
  response.json({ hashes: rows })
})
