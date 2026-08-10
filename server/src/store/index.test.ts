import { beforeEach, describe, expect, it } from 'vitest'
import { openSqlite } from './db'
import { Store } from './index'
import { parseCursor } from '../federation/protocol'
import { makeClaim, makeEntry, makeKey, makeRevocation, type TestKey } from '../testing/keys'

const key: TestKey = await makeKey('Alice', 'alice@example.org')
const other: TestKey = await makeKey('Bob', 'bob@example.org')

async function freshStore(): Promise<Store> {
  const store = new Store(await openSqlite(':memory:'))
  await store.ready()
  return store
}

let store: Store

beforeEach(async () => {
  store = await freshStore()
})

describe('schema', () => {
  it('is idempotent', async () => {
    await store.ready()
    await store.ready()
    await expect(store.health()).resolves.toBeUndefined()
  })
})

describe('identities and keys', () => {
  it('upserts by github id, following a rename', async () => {
    const first = await store.upsertIdentity({ githubId: 7, login: 'alice', avatarUrl: '' })
    const renamed = await store.upsertIdentity({ githubId: 7, login: 'alice-new', avatarUrl: '' })
    expect(renamed.id).toBe(first.id)
    expect(await store.identityByLogin('alice')).toBeNull()
    expect((await store.identityByLogin('alice-new'))?.id).toBe(first.id)
  })

  it('gives a local database exactly one identity', async () => {
    const one = await store.ensureLocalIdentity('me')
    const again = await store.ensureLocalIdentity('me')
    expect(again.id).toBe(one.id)
  })

  it('finds a key by fingerprint, locally or from a federated entry', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertKey(me.id, key.fingerprint, key.publicKey, 'github')
    expect(await store.keyByFingerprint(key.fingerprint)).toMatchObject({
      login: 'me',
      verifiedVia: 'github',
    })

    await store.upsertRemote(await makeEntry(other), 'https://b.example', Date.now())
    expect(await store.keyByFingerprint(other.fingerprint)).toMatchObject({ verifiedVia: 'remote' })
    expect(await store.keyByFingerprint('nothing here')).toBeNull()
  })
})

describe('certificates', () => {
  it('returns the timestamp exactly as it was signed', async () => {
    // The Lean CLI writes second precision.  Re-rendering it through a Date
    // adds `.000`, which changes the bytes a signature covers and makes every
    // certificate fail to verify anywhere but the machine that signed it.
    const me = await store.ensureLocalIdentity('me')
    const claim = makeClaim({ asserted: '2026-01-01T00:00:00Z' })
    await store.upsertCertificate({
      issuerId: me.id,
      claim,
      signature: 'sig',
      fingerprint: key.fingerprint,
      assurance: 'signed',
    })
    const [stored] = await store.localCertificates({ hash: claim.hash })
    expect(stored.claim.asserted).toBe('2026-01-01T00:00:00Z')
  })

  it('replaces a re-issued certificate rather than duplicating it', async () => {
    const me = await store.ensureLocalIdentity('me')
    for (const note of ['first', 'second']) {
      await store.upsertCertificate({
        issuerId: me.id,
        claim: makeClaim({ note }),
        signature: 'sig',
        fingerprint: key.fingerprint,
        assurance: 'signed',
      })
    }
    const found = await store.localCertificates({})
    expect(found).toHaveLength(1)
    expect(found[0].claim.note).toBe('second')
  })

  it('filters by hash, hasher and fingerprint', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertCertificate({
      issuerId: me.id,
      claim: makeClaim({ hash: 'aaaaaaaaaaaaaaaa' }),
      signature: 'sig',
      fingerprint: key.fingerprint,
      assurance: 'signed',
    })
    expect(await store.localCertificates({ hash: 'aaaaaaaaaaaaaaaa' })).toHaveLength(1)
    expect(await store.localCertificates({ hash: 'bbbbbbbbbbbbbbbb' })).toHaveLength(0)
    expect(await store.localCertificates({ hasher: 'nope' })).toHaveLength(0)
    expect(await store.localCertificates({ fingerprint: key.fingerprint })).toHaveLength(1)
    expect(await store.localCertificates({ fingerprint: other.fingerprint })).toHaveLength(0)
  })

  it('hides a revoked certificate', async () => {
    const me = await store.ensureLocalIdentity('me')
    const claim = makeClaim()
    await store.upsertCertificate({
      issuerId: me.id,
      claim,
      signature: 'sig',
      fingerprint: key.fingerprint,
      assurance: 'signed',
    })
    await store.revokeLocal(me.id, claim.hash)
    expect(await store.localCertificates({})).toHaveLength(0)
  })
})

describe('export', () => {
  async function seed(count: number): Promise<void> {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertKey(me.id, key.fingerprint, key.publicKey, 'self')
    for (let index = 0; index < count; index++) {
      await store.upsertCertificate({
        issuerId: me.id,
        claim: makeClaim({ hash: `${index}`.padStart(16, '0') }),
        signature: 'sig',
        fingerprint: key.fingerprint,
        assurance: 'signed',
      })
    }
  }

  it('never exports an attested certificate', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertKey(me.id, key.fingerprint, key.publicKey, 'self')
    await store.upsertCertificate({
      issuerId: me.id,
      claim: makeClaim(),
      signature: null,
      fingerprint: null,
      assurance: 'attested',
    })
    const page = await store.exportCertificates(null, 100)
    expect(page.certificates).toHaveLength(0)
  })

  it('pages without losing or repeating rows', async () => {
    await seed(25)
    const seen: string[] = []
    let cursor: string | undefined
    let complete = false
    for (let round = 0; round < 10 && !complete; round++) {
      const page = await store.exportCertificates(parseCursor(cursor), 10)
      seen.push(...page.certificates.map((certificate) => certificate.claim.hash))
      cursor = page.cursor
      complete = page.complete
    }
    expect(complete).toBe(true)
    expect(seen).toHaveLength(25)
    expect(new Set(seen).size).toBe(25)
  })

  it('reports truncation honestly', async () => {
    await seed(12)
    expect((await store.exportCertificates(null, 10)).complete).toBe(false)
    expect((await store.exportCertificates(null, 20)).complete).toBe(true)
  })

  it('returns nothing new to a caller that is up to date', async () => {
    await seed(3)
    const first = await store.exportCertificates(null, 10)
    const second = await store.exportCertificates(parseCursor(first.cursor), 10)
    expect(second.certificates).toHaveLength(0)
    expect(second.cursor).toBe(first.cursor)
  })
})

describe('remote certificates', () => {
  it('keeps the later assertion and ignores an older one', async () => {
    const newer = await makeEntry(key, { asserted: '2026-06-01T00:00:00Z', note: 'newer' })
    const older = await makeEntry(key, { asserted: '2026-01-01T00:00:00Z', note: 'older' })
    await store.upsertRemote(newer, 'https://b.example', Date.now())
    await store.upsertRemote(older, 'https://b.example', Date.now())
    const found = await store.remoteCertificates({})
    expect(found).toHaveLength(1)
    expect(found[0].claim.note).toBe('newer')
  })

  it('stores the assertion timestamp verbatim', async () => {
    await store.upsertRemote(
      await makeEntry(key, { asserted: '2026-06-01T00:00:00Z' }),
      'https://b.example',
      Date.now(),
    )
    expect((await store.remoteCertificates({}))[0].claim.asserted).toBe('2026-06-01T00:00:00Z')
  })

  it('reports freshness per question, so an unasked one is not cached', async () => {
    const at = Date.now()
    await store.upsertRemote(await makeEntry(key), 'https://b.example', at)
    expect(await store.remoteFreshness({ hash: '4e36146e78af9850' })).toBe(at)
    expect(await store.remoteFreshness({ hash: 'ffffffffffffffff' })).toBe(0)
  })
})

describe('revocations', () => {
  it('keeps the latest withdrawal for a key, hash and hasher', async () => {
    await store.upsertRevocation(await makeRevocation(key, { revoked: '2026-01-01T00:00:00Z' }))
    await store.upsertRevocation(
      await makeRevocation(key, { revoked: '2026-05-01T00:00:00Z', reason: 'later' }),
    )
    const found = await store.revocations({})
    expect(found).toHaveLength(1)
    expect(found[0].revocation.reason).toBe('later')

    // An older one arriving afterwards must not move the withdrawal backwards.
    await store.upsertRevocation(
      await makeRevocation(key, { revoked: '2026-02-01T00:00:00Z', reason: 'stale' }),
    )
    expect((await store.revocations({}))[0].revocation.reason).toBe('later')
  })
})

describe('trust lists', () => {
  it('follows a login, and refuses one nobody here has published under', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertIdentity({ githubId: 2, login: 'alice', avatarUrl: '' })
    expect(await store.followLogin(me.id, 'alice')).toBe(true)
    expect(await store.followLogin(me.id, 'nobody')).toBe(false)
    expect(await store.listFollows(me.id)).toEqual([{ login: 'alice', avatarUrl: '' }])
    await store.unfollowLogin(me.id, 'alice')
    expect(await store.listFollows(me.id)).toEqual([])
  })

  it('follows a key, which is the portable form', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.followKey(me.id, key.fingerprint.toUpperCase(), 'Alice')
    // Stored lower-case, so the two spellings are one follow.
    expect(await store.listKeyFollows(me.id)).toEqual([
      { fingerprint: key.fingerprint, label: 'Alice' },
    ])
    await store.unfollowKey(me.id, key.fingerprint)
    expect(await store.listKeyFollows(me.id)).toEqual([])
  })

  it('counts a federated certificate when its key is followed', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertRemote(
      await makeEntry(other, { hash: 'cccccccccccccccc' }),
      'https://b.example',
      Date.now(),
    )
    expect(await store.trustedHashes(me.id)).toEqual([])
    await store.followKey(me.id, other.fingerprint, '')
    expect(await store.trustedHashes(me.id)).toMatchObject([{ hash: 'cccccccccccccccc' }])
  })

  it('does not count a certificate from somebody you merely heard about', async () => {
    const me = await store.ensureLocalIdentity('me')
    const stranger = await store.upsertIdentity({ githubId: 3, login: 'stranger', avatarUrl: '' })
    await store.upsertCertificate({
      issuerId: stranger.id,
      claim: makeClaim(),
      signature: 'sig',
      fingerprint: key.fingerprint,
      assurance: 'signed',
    })
    expect(await store.trustedHashes(me.id)).toEqual([])
  })

  it('filters by hasher, since hashes from different hashers never compare', async () => {
    const me = await store.ensureLocalIdentity('me')
    await store.upsertRemote(
      await makeEntry(other, { hasher: 'structural' }),
      'https://b.example',
      Date.now(),
    )
    await store.followKey(me.id, other.fingerprint, '')
    expect(await store.trustedHashes(me.id, 'semantic_hash')).toEqual([])
    expect(await store.trustedHashes(me.id, 'structural')).toHaveLength(1)
  })
})

describe('peers', () => {
  it('records, lists by status, and never promotes on its own', async () => {
    await store.upsertPeer('https://a.example', 'a', 'seed')
    await store.upsertPeer('https://b.example', 'b', 'candidate')
    expect(await store.listPeers(['seed', 'active'])).toHaveLength(1)
    // Re-announcing must not upgrade a candidate to something queried.
    await store.upsertPeer('https://b.example', 'b renamed', 'active')
    expect((await store.peerByUrl('https://b.example'))?.status).toBe('candidate')
    expect((await store.peerByUrl('https://b.example'))?.name).toBe('b renamed')

    await store.setPeerStatus('https://b.example', 'active')
    expect(await store.listPeers(['seed', 'active'])).toHaveLength(2)
  })

  it('remembers where a sync got to', async () => {
    await store.upsertPeer('https://a.example', 'a', 'seed')
    await store.notePeerSeen('https://a.example', '123.4', '')
    expect((await store.peerByUrl('https://a.example'))?.cursor).toBe('123.4')
  })
})
