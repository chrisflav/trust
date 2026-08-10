/**
 * Three real nodes, over real HTTP, on loopback.
 *
 * Every other test in this directory checks a rule in isolation.  This one
 * checks the thing the rules exist for: that a certificate written on one node
 * can be found on another, that a forged one cannot, and that asking a question
 * of a node which does not know the answer reaches one that does.
 *
 * The nodes run in local mode, which is what makes them addressable on
 * `127.0.0.1` at all — and is itself worth exercising, since it is the
 * configuration a person keeping their own database will use.
 */

import { createServer } from 'node:net'
import type { Server } from 'node:http'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createApp } from '../index'
import { loadConfig, type Config } from '../config'
import { openSqlite } from '../store/db'
import { Store } from '../store'
import { canonicalClaim, canonicalRevocation, type Revocation } from '../certificate'
import { makeClaim, makeKey, sign, type TestKey } from '../testing/keys'

interface Node {
  url: string
  config: Config
  store: Store
  server: Server
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer()
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address()
      const port = typeof address === 'object' && address ? address.port : 0
      probe.close(() => resolve(port))
    })
  })
}

async function startNode(name: string, overrides: Partial<Config['policy']> = {}): Promise<Node> {
  const port = await freePort()
  const url = `http://127.0.0.1:${port}`
  const config: Config = {
    ...loadConfig({ TRUST_LOCAL: 'true', PORT: String(port), NODE_NAME: name, PUBLIC_URL: url }),
    policy: {
      ...loadConfig({ TRUST_LOCAL: 'true' }).policy,
      // Short enough that a test does not wait on a peer that will not answer.
      peerTimeoutMs: 2000,
      queryBudgetMs: 4000,
      // Every query in these tests should actually go out, not be answered from
      // a cache filled by the test before it.
      remoteTtlS: 0,
      allowPrivate: true,
      ...overrides,
    },
  }
  const store = new Store(await openSqlite(':memory:'))
  await store.ready()
  const server = await new Promise<Server>((resolve) => {
    const listening = createApp(config, store).listen(port, '127.0.0.1', () => resolve(listening))
  })
  return { url, config, store, server }
}

async function stop(node: Node): Promise<void> {
  await new Promise<void>((resolve) => node.server.close(() => resolve()))
  await node.store.close()
}

async function call(
  url: string,
  init?: RequestInit & { json?: unknown },
): Promise<{ status: number; body: any }> {
  const response = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    body: init?.json === undefined ? init?.body : JSON.stringify(init.json),
  })
  const text = await response.text()
  return { status: response.status, body: text ? JSON.parse(text) : null }
}

/**
 * Publish a signed certificate to a node, the way a client does.
 *
 * The result is asserted here rather than at the call sites: a claim the server
 * rejects — a hash with a stray non-hex character in it, say — otherwise turns
 * every later assertion into a vacuous one that passes for the wrong reason.
 */
async function publish(
  node: Node,
  key: TestKey,
  claim = makeClaim(),
): Promise<{ status: number; body: any }> {
  await call(`${node.url}/api/keys`, { method: 'POST', json: { armored: key.publicKey } })
  const result = await call(`${node.url}/api/certificates`, {
    method: 'POST',
    json: { claim, signature: await sign(key, canonicalClaim(claim)) },
  })
  expect(result.body, `publishing ${claim.hash}`).toMatchObject({ ok: true })
  return result
}

let alice: TestKey
let mallory: TestKey
let a: Node
let b: Node
let c: Node

beforeAll(async () => {
  ;[alice, mallory] = await Promise.all([makeKey('Alice'), makeKey('Mallory')])
  ;[a, b, c] = await Promise.all([startNode('a'), startNode('b'), startNode('c')])
}, 30_000)

afterAll(async () => {
  await Promise.all([a, b, c].filter(Boolean).map(stop))
})

describe('a node on its own', () => {
  it('describes itself', async () => {
    const { body } = await call(`${a.url}/api/federation`)
    expect(body).toMatchObject({ protocol: 'trust/1', url: a.url, name: 'a' })
  })

  it('publishes and finds a signed certificate', async () => {
    const published = await publish(a, alice)
    expect(published.body).toMatchObject({ ok: true, assurance: 'signed' })

    const { body } = await call(`${a.url}/api/certificates?hash=${makeClaim().hash}`)
    expect(body.certificates).toHaveLength(1)
    expect(body.certificates[0]).toMatchObject({
      assurance: 'signed',
      fingerprint: alice.fingerprint,
      provenance: { local: true },
    })
  })

  it('returns bytes that re-verify against what was signed', async () => {
    const { body } = await call(`${a.url}/api/certificates?hash=${makeClaim().hash}`)
    const certificate = body.certificates[0]
    // The whole point of returning `canonical`: a reader recomputes it from the
    // claim and must get the same bytes, or the signature it carries is useless.
    expect(certificate.canonical).toBe(canonicalClaim(certificate.claim))
  })
})

describe('pulling from a peer', () => {
  it('carries a signed certificate from one node to another', async () => {
    await b.store.upsertPeer(a.url, 'a', 'seed')
    const pulled = await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })
    expect(pulled.body.pulled[0]).toMatchObject({ ok: true, accepted: 1, rejected: 0 })

    const { body } = await call(`${b.url}/api/certificates?hash=${makeClaim().hash}&depth=0`)
    expect(body.certificates).toHaveLength(1)
    expect(body.certificates[0]).toMatchObject({
      fingerprint: alice.fingerprint,
      assurance: 'signed',
      provenance: { local: false, fromPeer: a.url, verifiedHere: true },
    })
  })

  it('resumes from its cursor instead of re-reading everything', async () => {
    const again = await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })
    expect(again.body.pulled[0]).toMatchObject({ accepted: 0, rejected: 0 })
  })

  it('never exports an attested certificate', async () => {
    // Published without a signature: nothing for anyone else to check.
    const claim = makeClaim({ hash: 'a11e51ed00000000', decl: 'Only.Attested' })
    await call(`${a.url}/api/certificates`, { method: 'POST', json: { claim } })
    const { body } = await call(`${a.url}/api/certificates/export`)
    expect(body.entries.some((entry: any) => entry.claim.hash === claim.hash)).toBe(false)

    // …and it is still visible on the node that made it.
    const local = await call(`${a.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(local.body.certificates[0]).toMatchObject({ assurance: 'attested' })
  })
})

describe('what a node refuses to believe', () => {
  it('rejects an entry whose claim was altered after signing', async () => {
    const claim = makeClaim({ hash: 'beefbeefbeefbeef' })
    const entry = {
      claim,
      signature: await sign(mallory, canonicalClaim(claim)),
      key: mallory.publicKey,
      fingerprint: mallory.fingerprint,
    }
    const tampered = { ...entry, claim: { ...claim, note: 'trust me' } }
    const { body } = await call(`${b.url}/api/import`, {
      method: 'POST',
      json: { protocol: 'trust/1', entries: [tampered], revocations: [] },
    })
    expect(body).toMatchObject({ accepted: 0, rejected: 1 })
    expect(body.reasons[0]).toMatch(/signature did not verify/)

    const found = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(found.body.certificates).toHaveLength(0)
  })

  it('keeps the honest entries in a bundle that also carries a forgery', async () => {
    const good = makeClaim({ hash: '900d900d900d900d' })
    const bad = makeClaim({ hash: 'badbadbadbadbad0' })
    const { body } = await call(`${b.url}/api/import`, {
      method: 'POST',
      json: {
        protocol: 'trust/1',
        entries: [
          {
            claim: good,
            signature: await sign(mallory, canonicalClaim(good)),
            key: mallory.publicKey,
            fingerprint: mallory.fingerprint,
          },
          {
            claim: bad,
            signature: await sign(mallory, canonicalClaim(makeClaim())),
            key: mallory.publicKey,
            fingerprint: mallory.fingerprint,
          },
        ],
        revocations: [],
      },
    })
    expect(body).toMatchObject({ accepted: 1, rejected: 1 })
  })

  it('refuses a bundle of an unknown protocol version', async () => {
    const { status } = await call(`${b.url}/api/import`, {
      method: 'POST',
      json: { protocol: 'trust/99', entries: [] },
    })
    expect(status).toBe(400)
  })
})

describe('delegated query', () => {
  it('reaches a node two hops away', async () => {
    // c knows only b; b knows a; the certificate is on a.
    await c.store.upsertPeer(b.url, 'b', 'seed')
    const claim = makeClaim({ hash: 'deadbeef0000cafe', decl: 'Far.Away' })
    await publish(a, alice, claim)

    const { body } = await call(`${c.url}/api/certificates?hash=${claim.hash}&depth=2`)
    expect(body.certificates).toHaveLength(1)
    expect(body.certificates[0]).toMatchObject({
      fingerprint: alice.fingerprint,
      provenance: { local: false, verifiedHere: true },
    })
    expect(body.askedPeers).toBe(1)
  })

  it('does not relay at all when asked for depth 0', async () => {
    const claim = makeClaim({ hash: '0000000000000001', decl: 'Not.Relayed' })
    await publish(a, alice, claim)
    const { body } = await call(`${c.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(body.certificates).toHaveLength(0)
    expect(body.askedPeers).toBe(0)
  })

  it('refuses to relay to a node already in the chain', async () => {
    // b's peer list contains a; telling b that a has already been asked must
    // leave it with nobody to ask.
    const claim = makeClaim({ hash: '0000000000000002', decl: 'Loop.Guard' })
    await publish(a, alice, claim)
    const via = encodeURIComponent(a.url)
    const { body } = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=2&via=${via}`)
    expect(body.askedPeers).toBe(0)
  })

  it('answers locally when it finds itself in the chain', async () => {
    const claim = makeClaim({ hash: '0000000000000003' })
    const via = encodeURIComponent(b.url)
    const { body } = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=2&via=${via}`)
    expect(body.askedPeers).toBe(0)
  })

  it('says so when an answer may be short', async () => {
    // A peer that is not listening: the query must come back, and must not
    // claim that nobody vouches for the hash.
    const dead = await freePort()
    await c.store.upsertPeer(`http://127.0.0.1:${dead}`, 'gone', 'seed')
    const { body } = await call(`${c.url}/api/certificates?hash=00000000000000ff&depth=1`)
    expect(body.truncated).toBe(true)
    await c.store.setPeerStatus(`http://127.0.0.1:${dead}`, 'blocked')
  }, 15_000)
})

describe('discovery', () => {
  it('records a node that announces itself honestly', async () => {
    const { body } = await call(`${b.url}/api/peers/announce`, { method: 'POST', json: { url: c.url } })
    // Not queried: autodiscover is off, so discovery may only propose.
    expect(body).toMatchObject({ url: c.url, name: 'c', status: 'candidate' })
    const listed = await call(`${b.url}/api/peers`)
    expect(listed.body.peers.map((peer: any) => peer.url)).not.toContain(c.url)
  })

  it('refuses a URL whose node calls itself something else', async () => {
    // The check that stops this endpoint being used as a scanner: `a` answers
    // here, but its descriptor says it lives at `a.url`, not at this alias.
    const alias = a.url.replace('127.0.0.1', 'localhost')
    const { status, body } = await call(`${b.url}/api/peers/announce`, {
      method: 'POST',
      json: { url: alias },
    })
    expect(status).toBe(400)
    expect(body.error).toMatch(/calls itself something else/)
  })

  it('refuses a URL that is not a node at all', async () => {
    const nowhere = `http://127.0.0.1:${await freePort()}`
    const { status } = await call(`${b.url}/api/peers/announce`, {
      method: 'POST',
      json: { url: nowhere },
    })
    expect(status).toBe(400)
  })

  it('lists only the peers it actually queries', async () => {
    const { body } = await call(`${b.url}/api/peers`)
    expect(body.peers.map((peer: any) => peer.url)).toEqual([a.url])
  })
})

describe('revocation', () => {
  it('travels, and withdraws the certificate everywhere it reached', async () => {
    const claim = makeClaim({ hash: 'cafecafecafecafe', decl: 'Will.Be.Withdrawn' })
    await publish(a, alice, claim)
    await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })
    const before = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(before.body.certificates).toHaveLength(1)

    const revocation: Revocation = {
      fingerprint: alice.fingerprint,
      hash: claim.hash,
      hasher: claim.hasher,
      reason: 'the proof was wrong',
      revoked: new Date(Date.parse(claim.asserted) + 86_400_000).toISOString(),
    }
    const published = await call(`${a.url}/api/revocations`, {
      method: 'POST',
      json: { revocation, signature: await sign(alice, canonicalRevocation(revocation)) },
    })
    expect(published.status).toBe(200)

    await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })
    const after = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(after.body.certificates).toHaveLength(0)
  })

  it('refuses one signed by anybody but the key it withdraws', async () => {
    const revocation: Revocation = {
      fingerprint: alice.fingerprint,
      hash: makeClaim().hash,
      hasher: 'semantic_hash',
      reason: 'not mine to withdraw',
      revoked: '2027-01-01T00:00:00Z',
    }
    const { status, body } = await call(`${a.url}/api/revocations`, {
      method: 'POST',
      json: {
        revocation,
        signature: await sign(mallory, canonicalRevocation(revocation)),
        key: mallory.publicKey,
      },
    })
    expect(status).toBe(400)
    expect(body.error).toMatch(/signed by the key it withdraws/)
  })

  it('lets a later assertion reinstate what an older revocation withdrew', async () => {
    const claim = makeClaim({
      hash: 'cafecafecafecafe',
      decl: 'Will.Be.Withdrawn',
      asserted: '2030-01-01T00:00:00Z',
      note: 'checked again, properly this time',
    })
    await publish(a, alice, claim)
    await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })
    const { body } = await call(`${b.url}/api/certificates?hash=${claim.hash}&depth=0`)
    expect(body.certificates).toHaveLength(1)
    expect(body.certificates[0].claim.note).toBe('checked again, properly this time')
  })
})

describe('trust lists', () => {
  it('counts a federated certificate once its key is followed', async () => {
    const claim = makeClaim({ hash: 'f0110ed000000000', decl: 'Followed.Key' })
    await publish(a, alice, claim)
    await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })

    const before = await call(`${b.url}/api/trusted`)
    expect(before.body.hashes.map((row: any) => row.hash)).not.toContain(claim.hash)

    await call(`${b.url}/api/trust-keys/${alice.fingerprint}`, {
      method: 'POST',
      json: { label: 'Alice' },
    })
    const after = await call(`${b.url}/api/trusted`)
    expect(after.body.hashes.map((row: any) => row.hash)).toContain(claim.hash)
  })

  it('does not enrol the people that key follows', async () => {
    // a follows mallory; b follows alice.  Nothing mallory signs may reach b.
    const claim = makeClaim({ hash: '3daf0e0000000000', decl: 'Third.Party' })
    await publish(a, mallory, claim)
    await call(`${a.url}/api/trust-keys/${mallory.fingerprint}`, { method: 'POST', json: {} })
    await call(`${b.url}/api/peers/pull`, { method: 'POST', json: {} })

    const { body } = await call(`${b.url}/api/trusted`)
    expect(body.hashes.map((row: any) => row.hash)).not.toContain(claim.hash)
  })
})
