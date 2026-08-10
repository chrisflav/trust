/**
 * Key material for tests.
 *
 * Generated rather than checked in: a private key in a repository is a bad
 * habit even when it guards nothing, and curve25519 generation is fast enough
 * that the tests do not notice.  Everything here is deliberately usable only
 * from tests — nothing in `src/` outside this directory imports it.
 */

import * as openpgp from 'openpgp'
import { canonicalClaim, canonicalRevocation, type Claim, type Revocation } from '../certificate'
import type { Entry, RevocationEntry } from '../federation/protocol'

export interface TestKey {
  fingerprint: string
  publicKey: string
  privateKey: openpgp.PrivateKey
}

export async function makeKey(name = 'Test User', email = 'test@example.org'): Promise<TestKey> {
  const { privateKey } = await openpgp.generateKey({
    // Fast enough that generating a fresh key per test run is not noticeable,
    // which is what lets no key material live in the repository.
    type: 'ecc',
    curve: 'ed25519Legacy',
    userIDs: [{ name, email }],
    format: 'object',
  })
  return {
    fingerprint: privateKey.getFingerprint().toLowerCase(),
    publicKey: privateKey.toPublic().armor(),
    privateKey,
  }
}

export async function sign(key: TestKey, text: string): Promise<string> {
  return (await openpgp.sign({
    message: await openpgp.createMessage({ text }),
    signingKeys: key.privateKey,
    detached: true,
    format: 'armored',
  })) as string
}

export function makeClaim(overrides: Partial<Claim> = {}): Claim {
  return {
    decl: 'Nat.gcd',
    hash: '4e36146e78af9850',
    hasher: 'semantic_hash',
    repo: 'core',
    commit: '5f6b07a',
    toolchain: '4.31.0',
    asserted: '2026-01-01T00:00:00Z',
    note: '',
    ...overrides,
  }
}

export async function makeEntry(key: TestKey, overrides: Partial<Claim> = {}): Promise<Entry> {
  const claim = makeClaim(overrides)
  return {
    claim,
    signature: await sign(key, canonicalClaim(claim)),
    key: key.publicKey,
    fingerprint: key.fingerprint,
  }
}

export async function makeRevocation(
  key: TestKey,
  overrides: Partial<Revocation> = {},
): Promise<RevocationEntry> {
  const revocation: Revocation = {
    fingerprint: key.fingerprint,
    hash: '4e36146e78af9850',
    hasher: 'semantic_hash',
    reason: '',
    revoked: '2026-02-01T00:00:00Z',
    ...overrides,
  }
  return {
    revocation,
    signature: await sign(key, canonicalRevocation(revocation)),
    key: key.publicKey,
    fingerprint: key.fingerprint,
  }
}
