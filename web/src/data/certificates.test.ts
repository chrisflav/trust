import { describe, expect, it } from 'vitest'
import * as openpgp from 'openpgp'
import { canonicalClaim, verifyHere, type Certificate, type Claim } from './certificates'

/**
 * A claim canonicalised by `Trust/Cert.lean`, copied verbatim.
 *
 * The bytes a signature covers are produced independently in Lean, in the
 * server and here.  A signature made against one and checked against another is
 * only valid if all three agree exactly, so this pins the browser's version to
 * output the Lean one actually emitted — including the awkward characters,
 * which is where implementations diverge.
 */
const GOLDEN_CLAIM: Claim = {
  decl: 'Nat.gcd',
  hash: '629db3ae6e206484',
  hasher: 'semantic-v1',
  repo: 'trust',
  commit: '0a5a0e6',
  toolchain: '4.31.0',
  asserted: '2026-07-18T16:14:12Z',
  note: 'reviewed by hand: "quotes", \\backslash, and ünïcodé',
}

const GOLDEN_CANONICAL =
  '{"asserted":"2026-07-18T16:14:12Z","commit":"0a5a0e6","decl":"Nat.gcd",' +
  '"hash":"629db3ae6e206484","hasher":"semantic-v1",' +
  '"note":"reviewed by hand: \\"quotes\\", \\\\backslash, and ünïcodé",' +
  '"repo":"trust","toolchain":"4.31.0"}'

describe('canonicalClaim', () => {
  it('matches the bytes the Lean implementation produced', () => {
    expect(canonicalClaim(GOLDEN_CLAIM)).toBe(GOLDEN_CANONICAL)
  })

  it('does not depend on the order the claim was built in', () => {
    const shuffled: Claim = {
      note: GOLDEN_CLAIM.note,
      toolchain: GOLDEN_CLAIM.toolchain,
      asserted: GOLDEN_CLAIM.asserted,
      commit: GOLDEN_CLAIM.commit,
      repo: GOLDEN_CLAIM.repo,
      hasher: GOLDEN_CLAIM.hasher,
      hash: GOLDEN_CLAIM.hash,
      decl: GOLDEN_CLAIM.decl,
    }
    expect(canonicalClaim(shuffled)).toBe(GOLDEN_CANONICAL)
  })

  it('distinguishes claims that differ anywhere', () => {
    for (const field of Object.keys(GOLDEN_CLAIM) as (keyof Claim)[]) {
      const altered = { ...GOLDEN_CLAIM, [field]: `${GOLDEN_CLAIM[field]}x` }
      expect(canonicalClaim(altered)).not.toBe(GOLDEN_CANONICAL)
    }
  })

  it('escapes a note that tries to forge extra fields', () => {
    // A note is free text from a person; it must not be able to close the
    // string and add claims of its own.
    const hostile: Claim = { ...GOLDEN_CLAIM, note: '","hash":"0000000000000000' }
    const parsed = JSON.parse(canonicalClaim(hostile))
    // The note stays one string, and the hash is still the real one.
    expect(parsed.hash).toBe(GOLDEN_CLAIM.hash)
    expect(parsed.note).toBe(hostile.note)
    expect(Object.keys(parsed)).toHaveLength(8)
  })

})

/**
 * Checking a certificate in the page, rather than believing the server.
 *
 * This is the difference between "a server told me this is signed" and "I
 * watched the signature verify", and it is the only one of the two that means
 * anything when the server is the thing you are unsure about.  So the tests are
 * about what it refuses, not about what it accepts.
 */
// Generated rather than checked in: a key in a repository is a bad habit even
// when it guards nothing, and curve25519 is fast enough not to be noticed.
const key = await openpgp.generateKey({
  type: 'ecc',
  curve: 'ed25519Legacy',
  userIDs: [{ name: 'Alice', email: 'alice@example.org' }],
  format: 'object',
})
const other = await openpgp.generateKey({
  type: 'ecc',
  curve: 'ed25519Legacy',
  userIDs: [{ name: 'Mallory', email: 'mallory@example.org' }],
  format: 'object',
})

describe('verifyHere', () => {
  async function certificateFor(
    claim: Claim,
    signWith = key.privateKey,
    carry = key.privateKey,
  ): Promise<Certificate> {
    const signature = (await openpgp.sign({
      message: await openpgp.createMessage({ text: canonicalClaim(claim) }),
      signingKeys: signWith,
      detached: true,
      format: 'armored',
    })) as string
    return {
      claim,
      issuer: 'alice',
      avatarUrl: '',
      signature,
      fingerprint: carry.getFingerprint().toLowerCase(),
      key: carry.toPublic().armor(),
      assurance: 'signed',
      keyVerifiedVia: 'self',
      canonical: canonicalClaim(claim),
      provenance: { local: false, origin: '', fromPeer: '', verifiedHere: true, fetchedAt: null },
    }
  }

  it('accepts a signature over the claim it is shown with', async () => {
    expect(await verifyHere(await certificateFor(GOLDEN_CLAIM))).toMatchObject({ ok: true })
  })

  it('rejects a claim altered after signing, however the server labelled it', async () => {
    const certificate = await certificateFor(GOLDEN_CLAIM)
    // The server says `signed`, and the canonical string it sent still matches
    // the signature — but the claim on display does not.  Recomputing the bytes
    // from the claim rather than trusting `canonical` is what catches this.
    const swapped: Certificate = {
      ...certificate,
      claim: { ...GOLDEN_CLAIM, hash: '0000000000000000' },
    }
    expect(await verifyHere(swapped)).toMatchObject({ ok: false })
  })

  it('rejects a signature made by a key other than the one carried', async () => {
    const certificate = await certificateFor(GOLDEN_CLAIM, other.privateKey, key.privateKey)
    expect(await verifyHere(certificate)).toMatchObject({ ok: false })
  })

  it('rejects a key that does not match the fingerprint claimed', async () => {
    const certificate = await certificateFor(GOLDEN_CLAIM)
    const relabelled = { ...certificate, fingerprint: other.privateKey.getFingerprint().toLowerCase() }
    expect(await verifyHere(relabelled)).toMatchObject({
      ok: false,
      reason: expect.stringContaining('fingerprint'),
    })
  })

  it('says plainly when there is nothing to check', async () => {
    const certificate = await certificateFor(GOLDEN_CLAIM)
    expect(await verifyHere({ ...certificate, signature: null })).toMatchObject({ ok: false })
    expect(await verifyHere({ ...certificate, key: null })).toMatchObject({
      ok: false,
      reason: expect.stringContaining('public key'),
    })
  })
})
