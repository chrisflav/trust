import { Router, type Request, type RequestHandler, type Response } from 'express'
import type { Config } from './config'
import type { Auth } from './auth'
import type { Store } from './store'
import {
  canonicalClaim,
  canonicalRevocation,
  parseClaim,
  parseRevocation,
  readPublicKey,
  verifyDetached,
  verifySignature,
} from './certificate'
import { isSuppressed, parseBundle, parseCursor, parseVia, PROTOCOL } from './federation/protocol'
import {
  announcePeer,
  answer,
  descriptorFor,
  discoverThrough,
  importBundle,
  pullFrom,
  pullFromAll,
  toEntry,
} from './federation/service'

/**
 * One path parameter, as a string.
 *
 * Express types a parameter as `string | string[]`, because a route *can*
 * declare a repeating one.  None of these do, and `String(…)` at every use site
 * would be noise that says nothing.
 */
function param(request: Request, name: string): string {
  const value = (request.params as Record<string, string | string[]>)[name]
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '')
}

export function createRoutes(config: Config, store: Store, auth: Auth): Router {
  const routes = Router()
  const { requireUser, currentUser } = auth

  /**
   * The operator's endpoints, closed unless a token is configured.
   *
   * Local mode has no separation to enforce: the only person who can reach the
   * server is the person whose database it is.
   */
  const requireOperator: RequestHandler = (request, response, next) => {
    if (config.local) return next()
    const header = request.headers.authorization ?? ''
    const offered = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
    if (config.adminToken.length === 0 || offered !== config.adminToken) {
      response.status(403).json({ error: 'this endpoint is the operator’s' })
      return
    }
    next()
  }

  routes.get('/api/health', async (_request, response) => {
    await store.health()
    response.json({ ok: true })
  })

  // ---------------------------------------------------------------- identity --

  routes.get('/auth/github', (_request, response) => {
    response.redirect(auth.authorizeUrl())
  })

  routes.get('/auth/github/callback', async (request, response) => {
    const { code, state } = request.query as { code?: string; state?: string }
    if (!code || !state || !auth.consumeState(state)) {
      response.status(400).json({ error: 'bad OAuth state' })
      return
    }
    try {
      const github = await auth.exchangeCode(code)
      const user = await store.upsertIdentity({
        githubId: github.id,
        login: github.login,
        avatarUrl: github.avatar_url ?? '',
      })
      auth.issueSession(response, user)
      response.redirect(config.appUrl || '/')
    } catch (error) {
      response.status(502).json({ error: String(error instanceof Error ? error.message : error) })
    }
  })

  routes.get('/api/me', async (request, response) => {
    const session = auth.readSession(request)
    if (session) {
      response.json({ user: session })
      return
    }
    // A local database has nobody to sign in as, and saying "signed out" would
    // send the frontend looking for an OAuth flow that does not exist here.
    if (config.local) {
      response.json({ user: await store.ensureLocalIdentity(config.name || 'local'), local: true })
      return
    }
    response.json({ user: null })
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
    const token = auth.newToken()
    await store.createToken(
      currentUser(request).id,
      auth.hashToken(token),
      typeof name === 'string' ? name.slice(0, 100) : '',
    )
    response.json({ token, note: 'copy this now; it is not stored and cannot be shown again' })
  })

  routes.get('/api/tokens', requireUser, async (request, response) => {
    response.json({ tokens: await store.listTokens(currentUser(request).id) })
  })

  routes.delete('/api/tokens/:id', requireUser, async (request, response) => {
    await store.deleteToken(currentUser(request).id, param(request, 'id'))
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
    const key = await readPublicKey(armored as string)
    if ('error' in key) {
      response.status(400).json({ error: key.error })
      return
    }
    const user = currentUser(request)
    const published = config.local ? [] : await auth.githubPublicKeys(user.login)
    const onGitHub = published.some(
      (candidate) => candidate.replace(/\s/g, '') === (armored as string).replace(/\s/g, ''),
    )
    const verifiedVia = onGitHub ? 'github' : 'self'
    await store.upsertKey(user.id, key.fingerprint, armored as string, verifiedVia)
    response.json({ fingerprint: key.fingerprint, verifiedVia })
  })

  routes.get('/api/keys/:login', async (request, response) => {
    response.json({ keys: await store.keysForLogin(param(request, 'login')) })
  })

  /**
   * A key by fingerprint, wherever this node saw it.
   *
   * Federated entries are attributed to a key, not to a name, so a reader
   * checking one needs to be able to ask for it that way.
   */
  routes.get('/api/key/:fingerprint', async (request, response) => {
    const key = await store.keyByFingerprint(param(request, 'fingerprint'))
    if (!key) {
      response.status(404).json({ error: 'no key here with that fingerprint' })
      return
    }
    response.json(key)
  })

  // ------------------------------------------------------------- certificates --

  /**
   * Publish a certificate.
   *
   * A signature is optional but is the whole point: unsigned, the row is only
   * this server's word that a logged-in account said something, is marked
   * `attested` so a reader can tell the difference, and — since there would be
   * nothing for anyone else to check — never federates.
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
      const verdict = await verifySignature(claim, body.signature, await store.keysForIdentity(user.id))
      if (!verdict.ok) {
        response.status(400).json({ error: `signature did not verify: ${verdict.reason}` })
        return
      }
      assurance = 'signed'
      fingerprint = verdict.fingerprint ?? null
    }
    await store.upsertCertificate({
      issuerId: user.id,
      claim,
      signature: body.signature ?? null,
      fingerprint,
      assurance,
    })
    response.json({ ok: true, assurance })
  })

  /**
   * Withdraw a certificate.
   *
   * Unsigned, this only hides the row here — which is all it can do, since a
   * copy that has already travelled is not this server's to take back.  A
   * signed revocation (`POST /api/revocations`) is the form that federates.
   */
  routes.delete('/api/certificates/:hash', requireUser, async (request, response) => {
    await store.revokeLocal(currentUser(request).id, param(request, 'hash'))
    response.json({ ok: true, note: 'withdrawn here; publish a signed revocation to withdraw it everywhere' })
  })

  /**
   * A signed withdrawal, which travels.
   *
   * Accepted from anyone, signed-in or not, because the signature is the
   * authorisation: only the key that made an assertion can withdraw it, and
   * requiring a session as well would mean a key-holder who has lost their
   * account can never take a certificate back.
   */
  routes.post('/api/revocations', async (request, response) => {
    const body = request.body as { revocation?: unknown; signature?: string; key?: string }
    const revocation = parseRevocation(body.revocation)
    if ('error' in revocation) {
      response.status(400).json({ error: revocation.error })
      return
    }
    const armored = body.key ?? (await store.keyByFingerprint(revocation.fingerprint))?.armored
    if (!armored) {
      response.status(400).json({ error: 'no key here with that fingerprint; send it with the revocation' })
      return
    }
    const key = await readPublicKey(armored)
    if ('error' in key) {
      response.status(400).json({ error: key.error })
      return
    }
    if (key.fingerprint !== revocation.fingerprint) {
      response.status(400).json({ error: 'a revocation must be signed by the key it withdraws' })
      return
    }
    const verdict = await verifyDetached(
      canonicalRevocation(revocation),
      body.signature ?? '',
      [armored],
    )
    if (!verdict.ok || verdict.fingerprint !== revocation.fingerprint) {
      response.status(400).json({ error: `signature did not verify: ${verdict.reason ?? 'wrong key'}` })
      return
    }
    await store.upsertRevocation({
      revocation,
      signature: body.signature ?? '',
      key: armored,
      fingerprint: key.fingerprint,
    })
    response.json({ ok: true, canonical: canonicalRevocation(revocation) })
  })

  /**
   * Who vouches for this declaration — here, and anywhere this node can reach.
   *
   * Returns the canonical claim bytes and the signature alongside the verdict,
   * so a client can repeat the check rather than take this server's word for
   * it.  `format=bundle` is the same answer in the shape a peer expects, which
   * is how a relayed entry ends up checked by exactly the same rules as an
   * imported one.
   */
  routes.get('/api/certificates', async (request, response) => {
    const query = request.query as Record<string, string | undefined>
    if (!query.hash && !query.fingerprint) {
      response.status(400).json({ error: 'hash or fingerprint is required' })
      return
    }
    const depth = query.depth === undefined ? config.policy.maxDepth : Number(query.depth)
    const result = await answer(store, config, {
      hash: query.hash,
      hasher: query.hasher,
      fingerprint: query.fingerprint,
      depth: Number.isFinite(depth) ? Math.max(0, depth) : 0,
      via: parseVia(query.via, config.policy.maxViaLength),
    })

    if (query.format === 'bundle') {
      response.json({
        protocol: PROTOCOL,
        origin: config.publicUrl,
        entries: result.certificates
          .filter((certificate) => certificate.assurance === 'signed')
          .map((certificate) => ({
            claim: certificate.claim,
            signature: certificate.signature,
            key: certificate.key,
            fingerprint: certificate.fingerprint,
            hints: {
              issuer: certificate.issuer,
              keyVerifiedVia: certificate.keyVerifiedVia ?? undefined,
              origin: certificate.provenance.origin || config.publicUrl,
            },
          })),
        revocations: (await store.revocations({ hash: query.hash, hasher: query.hasher })).map(
          (stored) => ({
            revocation: stored.revocation,
            signature: stored.signature,
            key: stored.armoredKey,
            fingerprint: stored.revocation.fingerprint,
          }),
        ),
        complete: !result.truncated,
      })
      return
    }

    response.json({
      certificates: result.certificates,
      truncated: result.truncated,
      askedPeers: result.askedPeers,
    })
  })

  // ------------------------------------------------------------- federation --

  routes.get('/api/federation', async (_request, response) => {
    response.json(descriptorFor(config, await store.counts()))
  })

  /**
   * Signed certificates, in cursor order, for a peer catching up.
   *
   * Public and unauthenticated: everything it returns is signed, and a
   * signature carries the same weight to a stranger as to a friend.
   */
  routes.get('/api/certificates/export', async (request, response) => {
    const query = request.query as Record<string, string | undefined>
    const limit = Math.min(Number(query.limit) || config.policy.maxEntries, config.policy.maxEntries)
    const after = parseCursor(query.since)
    const page = await store.exportCertificates(after, limit)
    const revocations = await store.exportRevocations(after, limit)
    response.json({
      protocol: PROTOCOL,
      origin: config.publicUrl,
      entries: page.certificates
        .map((certificate) => toEntry(certificate, config.publicUrl))
        .filter((entry) => entry !== null),
      revocations: revocations.map((stored) => ({
        revocation: stored.revocation,
        signature: stored.signature,
        key: stored.armoredKey,
        fingerprint: stored.revocation.fingerprint,
      })),
      cursor: page.cursor,
      complete: page.complete,
    })
  })

  /**
   * Accept a bundle somebody pushed.
   *
   * Every entry is checked against §3.4 before it is stored, so the worst an
   * open import endpoint can do is fill a disk — which is why it wants an
   * operator token on a public node, and nothing at all on a local one.
   */
  routes.post('/api/import', requireOperator, async (request, response) => {
    const bundle = parseBundle(request.body)
    if ('error' in bundle) {
      response.status(400).json({ error: bundle.error })
      return
    }
    response.json(await importBundle(store, bundle, bundle.origin ?? 'pushed'))
  })

  /** Peers this node actually queries.  Candidates and blocks stay private. */
  routes.get('/api/peers', async (_request, response) => {
    const peers = await store.listPeers(['seed', 'active'])
    response.json({
      peers: peers.map((peer) => ({
        url: peer.url,
        name: peer.name,
        lastSeen: peer.lastSeenMs ? new Date(peer.lastSeenMs).toISOString() : null,
      })),
    })
  })

  routes.post('/api/peers/announce', async (request, response) => {
    const { url } = request.body as { url?: string }
    if (typeof url !== 'string') {
      response.status(400).json({ error: 'url is required' })
      return
    }
    const result = await announcePeer(store, config, url)
    if ('error' in result) {
      response.status(400).json(result)
      return
    }
    response.json(result)
  })

  routes.get('/api/peers/all', requireOperator, async (_request, response) => {
    response.json({ peers: await store.listPeers() })
  })

  const PEER_STATUSES = ['seed', 'active', 'candidate', 'blocked'] as const

  routes.post('/api/peers/status/:status', requireOperator, async (request, response) => {
    const { url } = request.body as { url?: string }
    if (typeof url !== 'string') {
      response.status(400).json({ error: 'url is required' })
      return
    }
    // Validated here rather than in the path pattern: the two Express majors
    // spell an inline pattern differently, and a route that silently stops
    // matching is a worse failure than a 400.
    const status = param(request, 'status') as (typeof PEER_STATUSES)[number]
    if (!PEER_STATUSES.includes(status)) {
      response.status(400).json({ error: `status must be one of ${PEER_STATUSES.join(', ')}` })
      return
    }
    const existing = await store.peerByUrl(url)
    if (!existing) await store.upsertPeer(url, '', status)
    else await store.setPeerStatus(url, status)
    response.json({ ok: true, url, status })
  })

  routes.post('/api/peers/pull', requireOperator, async (request, response) => {
    const { url } = request.body as { url?: string }
    response.json({
      pulled: url ? [await pullFrom(store, config, url)] : await pullFromAll(store, config),
    })
  })

  routes.post('/api/peers/discover', requireOperator, async (request, response) => {
    const { url } = request.body as { url?: string }
    if (typeof url !== 'string') {
      response.status(400).json({ error: 'url is required' })
      return
    }
    response.json({ learned: await discoverThrough(store, config, url) })
  })

  // -------------------------------------------------------------- trust lists --

  routes.get('/api/trust-list', requireUser, async (request, response) => {
    const id = currentUser(request).id
    response.json({
      trusted: await store.listFollows(id),
      keys: await store.listKeyFollows(id),
    })
  })

  routes.post('/api/trust-list/:login', requireUser, async (request, response) => {
    const ok = await store.followLogin(currentUser(request).id, param(request, 'login'))
    if (!ok) {
      response.status(404).json({ error: 'nobody here by that name has published anything' })
      return
    }
    response.json({ ok: true })
  })

  routes.delete('/api/trust-list/:login', requireUser, async (request, response) => {
    await store.unfollowLogin(currentUser(request).id, param(request, 'login'))
    response.json({ ok: true })
  })

  /**
   * Follow a key.
   *
   * The portable half of a trust list: a login only means something on the
   * server that issued it, and a certificate that arrives from three hops away
   * carries a fingerprint and nothing else you could have checked.
   */
  routes.post('/api/trust-keys/:fingerprint', requireUser, async (request, response) => {
    const fingerprint = param(request, 'fingerprint').toLowerCase()
    if (!/^[0-9a-f]{16,64}$/.test(fingerprint)) {
      response.status(400).json({ error: 'that is not a fingerprint' })
      return
    }
    const { label } = request.body as { label?: string }
    await store.followKey(currentUser(request).id, fingerprint, (label ?? '').slice(0, 100))
    response.json({ ok: true })
  })

  routes.delete('/api/trust-keys/:fingerprint', requireUser, async (request, response) => {
    await store.unfollowKey(currentUser(request).id, param(request, 'fingerprint'))
    response.json({ ok: true })
  })

  /**
   * Every hash your trust list vouches for.
   *
   * What the frontend actually needs: one flat set it can turn into trusted
   * declarations.  Non-transitive by construction — the joins go one hop, so
   * trusting someone never silently enrols the people they trust, and
   * federation widens who you can hear from rather than whom you trust.
   */
  routes.get('/api/trusted', requireUser, async (request, response) => {
    const { hasher } = request.query as { hasher?: string }
    const hashes = await store.trustedHashes(currentUser(request).id, hasher)
    const revocations = await store.revocations({ hasher })
    response.json({
      // Withdrawals apply here too.  A trusted set that kept counting a
      // certificate its issuer had taken back would be the one place the
      // withdrawal did not arrive — and the place it matters most, since this
      // is what decides where a dependency tree stops.
      hashes: hashes.filter(
        (row) =>
          !isSuppressed(
            { fingerprint: row.fingerprint, claim: { ...row, asserted: row.asserted } },
            revocations,
          ),
      ),
    })
  })

  return routes
}

/** Exported for the tests, which assemble claims the same way a client does. */
export { canonicalClaim }
export type { Request, Response }
