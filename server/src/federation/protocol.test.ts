import { describe, expect, it } from 'vitest'
import {
  acceptEntry,
  acceptRevocation,
  dedupe,
  encodeCursor,
  isSuppressed,
  parseBundle,
  parseCursor,
  parseDescriptor,
  parseVia,
  PROTOCOL,
} from './protocol'
import { canonicalRevocation, type Revocation } from '../certificate'
import { makeClaim, makeEntry, makeKey, makeRevocation, sign, type TestKey } from '../testing/keys'

const key: TestKey = await makeKey('Alice', 'alice@example.org')
const other: TestKey = await makeKey('Mallory', 'mallory@example.org')

describe('acceptEntry', () => {
  it('accepts a well-formed signed entry', async () => {
    const accepted = await acceptEntry(await makeEntry(key))
    expect('error' in accepted).toBe(false)
    if ('error' in accepted) return
    expect(accepted.fingerprint).toBe(key.fingerprint)
    expect(accepted.claim.decl).toBe('Nat.gcd')
  })

  it('refuses an unsigned entry, however well formed', async () => {
    const entry = await makeEntry(key)
    const result = await acceptEntry({ ...entry, signature: undefined })
    expect(result).toMatchObject({ error: expect.stringContaining('unsigned') })
  })

  it('refuses an entry whose claim was altered after signing', async () => {
    const entry = await makeEntry(key)
    const tampered = { ...entry, claim: { ...entry.claim, hash: 'deadbeefdeadbeef' } }
    expect(await acceptEntry(tampered)).toMatchObject({
      error: expect.stringContaining('signature did not verify'),
    })
  })

  it('refuses an entry whose note was altered, not just its hash', async () => {
    const entry = await makeEntry(key)
    const tampered = { ...entry, claim: { ...entry.claim, note: 'reviewed by hand' } }
    expect(await acceptEntry(tampered)).toMatchObject({
      error: expect.stringContaining('signature did not verify'),
    })
  })

  it('refuses a fingerprint that does not match the key it travels with', async () => {
    const entry = await makeEntry(key)
    expect(await acceptEntry({ ...entry, fingerprint: other.fingerprint })).toMatchObject({
      error: expect.stringContaining('does not match'),
    })
  })

  it('refuses a signature made by a key other than the one carried', async () => {
    // Mallory's signature over Alice's claim, presented with Mallory's key —
    // internally consistent, and still not Alice's assertion.
    const claim = makeClaim()
    const entry = await makeEntry(key)
    const swapped = {
      ...entry,
      key: other.publicKey,
      fingerprint: other.fingerprint,
      claim,
    }
    expect(await acceptEntry(swapped)).toMatchObject({
      error: expect.stringContaining('signature did not verify'),
    })
  })

  it('refuses a private key block outright', async () => {
    const entry = await makeEntry(key)
    const leaked = { ...entry, key: key.privateKey.armor() }
    expect(await acceptEntry(leaked)).toMatchObject({
      error: expect.stringContaining('private key'),
    })
  })

  it('refuses a malformed claim before doing any cryptography', async () => {
    const entry = await makeEntry(key)
    expect(await acceptEntry({ ...entry, claim: { ...entry.claim, hash: 'NOT-HEX' } })).toMatchObject(
      { error: expect.stringContaining('lower-case hex') },
    )
  })

  it('refuses junk', async () => {
    expect(await acceptEntry(null)).toMatchObject({ error: expect.any(String) })
    expect(await acceptEntry('a string')).toMatchObject({ error: expect.any(String) })
    expect(await acceptEntry({})).toMatchObject({ error: expect.any(String) })
  })

  it('carries hints without letting them decide anything', async () => {
    const entry = await makeEntry(key)
    const accepted = await acceptEntry({
      ...entry,
      hints: { issuer: 'alice', keyVerifiedVia: 'github', bogus: 'ignored' },
    })
    if ('error' in accepted) throw new Error(accepted.error)
    expect(accepted.hints).toEqual({ issuer: 'alice', keyVerifiedVia: 'github' })
    expect(accepted.fingerprint).toBe(key.fingerprint)
  })
})

describe('acceptRevocation', () => {
  it('accepts one signed by the key it withdraws', async () => {
    const accepted = await acceptRevocation(await makeRevocation(key))
    expect('error' in accepted).toBe(false)
  })

  it('refuses one signed by somebody else', async () => {
    // Mallory writes a revocation naming Alice's key and signs it with her own.
    const revocation: Revocation = {
      fingerprint: key.fingerprint,
      hash: '4e36146e78af9850',
      hasher: 'semantic_hash',
      reason: 'not really',
      revoked: '2026-02-01T00:00:00Z',
    }
    const forged = {
      revocation,
      signature: await sign(other, canonicalRevocation(revocation)),
      key: other.publicKey,
      fingerprint: other.fingerprint,
    }
    expect(await acceptRevocation(forged)).toMatchObject({
      error: expect.stringContaining('must be signed by the key it withdraws'),
    })
  })
})

describe('isSuppressed', () => {
  it('withdraws a certificate asserted before the revocation', async () => {
    const entry = await makeEntry(key, { asserted: '2026-01-01T00:00:00Z' })
    const revocation = await makeRevocation(key, { revoked: '2026-02-01T00:00:00Z' })
    expect(isSuppressed(entry, [revocation])).toBe(true)
  })

  it('leaves a certificate re-issued afterwards standing', async () => {
    const entry = await makeEntry(key, { asserted: '2026-03-01T00:00:00Z' })
    const revocation = await makeRevocation(key, { revoked: '2026-02-01T00:00:00Z' })
    expect(isSuppressed(entry, [revocation])).toBe(false)
  })

  it('does not withdraw another key’s certificate for the same hash', async () => {
    const entry = await makeEntry(other, { asserted: '2026-01-01T00:00:00Z' })
    const revocation = await makeRevocation(key)
    expect(isSuppressed(entry, [revocation])).toBe(false)
  })

  it('does not cross hashers', async () => {
    const entry = await makeEntry(key, { hasher: 'structural' })
    const revocation = await makeRevocation(key, { hasher: 'semantic_hash' })
    expect(isSuppressed(entry, [revocation])).toBe(false)
  })
})

describe('dedupe', () => {
  const at = (asserted: string, fingerprint = 'aa', hash = 'bb') => ({
    fingerprint,
    claim: { hash, hasher: 'semantic_hash', asserted },
  })

  it('keeps the later assertion', () => {
    const kept = dedupe([at('2026-01-01T00:00:00Z'), at('2026-06-01T00:00:00Z')])
    expect(kept).toHaveLength(1)
    expect(kept[0].claim.asserted).toBe('2026-06-01T00:00:00Z')
  })

  it('keeps what came first on a tie, so gossip converges', () => {
    const first = at('2026-01-01T00:00:00Z')
    const second = { ...at('2026-01-01T00:00:00Z'), marker: 'second' }
    expect(dedupe([first, second])[0]).toBe(first)
  })

  it('separates different keys, hashes and hashers', () => {
    expect(
      dedupe([
        at('2026-01-01T00:00:00Z', 'aa', 'bb'),
        at('2026-01-01T00:00:00Z', 'cc', 'bb'),
        at('2026-01-01T00:00:00Z', 'aa', 'dd'),
      ]),
    ).toHaveLength(3)
  })
})

describe('parseBundle', () => {
  it('refuses an unknown protocol version', () => {
    expect(parseBundle({ protocol: 'trust/99', entries: [] })).toMatchObject({
      error: expect.stringContaining('unknown protocol'),
    })
    expect(parseBundle({ entries: [] })).toMatchObject({ error: expect.any(String) })
  })

  it('treats a missing `complete` as complete and an explicit false as truncated', () => {
    expect(parseBundle({ protocol: PROTOCOL, entries: [] })).toMatchObject({ complete: true })
    expect(parseBundle({ protocol: PROTOCOL, entries: [], complete: false })).toMatchObject({
      complete: false,
    })
  })

  it('tolerates missing arrays rather than throwing', () => {
    const bundle = parseBundle({ protocol: PROTOCOL })
    if ('error' in bundle) throw new Error(bundle.error)
    expect(bundle.entries).toEqual([])
    expect(bundle.revocations).toEqual([])
  })
})

describe('parseDescriptor', () => {
  it('requires a protocol and a url', () => {
    expect(parseDescriptor({ protocol: PROTOCOL })).toMatchObject({ error: 'descriptor has no url' })
    expect(parseDescriptor({ url: 'https://a.example' })).toMatchObject({ error: expect.any(String) })
  })

  it('falls back to the host for a nameless node', () => {
    const descriptor = parseDescriptor({ protocol: PROTOCOL, url: 'https://a.example' })
    if ('error' in descriptor) throw new Error(descriptor.error)
    expect(descriptor.name).toBe('a.example')
  })
})

describe('cursors', () => {
  it('round-trips', () => {
    expect(parseCursor(encodeCursor(1717171717123, 42))).toEqual({ ms: 1717171717123, id: 42 })
  })

  it('rejects anything that is not one', () => {
    for (const bad of ['', 'abc', '1717171717', '1.2.3', null, 12, '-1.2']) {
      expect(parseCursor(bad)).toBeNull()
    }
  })
})

describe('parseVia', () => {
  it('normalises trailing slashes so a node recognises itself', () => {
    expect(parseVia('https://a.example/,https://b.example', 8)).toEqual([
      'https://a.example',
      'https://b.example',
    ])
  })

  it('caps the chain', () => {
    const long = Array.from({ length: 20 }, (_, i) => `https://n${i}.example`).join(',')
    expect(parseVia(long, 8)).toHaveLength(8)
  })

  it('is empty for absent or junk input', () => {
    expect(parseVia(undefined, 8)).toEqual([])
    expect(parseVia('', 8)).toEqual([])
    expect(parseVia(42, 8)).toEqual([])
  })
})
