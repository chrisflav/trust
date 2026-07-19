import { describe, expect, it } from 'vitest'
import { canonicalClaim, type Claim } from './certificates'

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
