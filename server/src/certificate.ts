import * as openpgp from 'openpgp'

/**
 * A trust certificate: one person's assertion about one declaration.
 *
 * Keyed by the semantic hash rather than by name.  Names move between
 * refactors, and the hash does not: `semantic_hash` computes it over the
 * definitional closure, so a declaration's hash incorporates the hashes of
 * everything it references.  A certificate therefore vouches for the whole
 * subtree beneath a declaration, and any change in meaning underneath
 * invalidates it without anyone having to notice.
 *
 * It also means a certificate written against one repository applies to any
 * other where that declaration still hashes the same, which is the only reason
 * sharing them is worth anything.
 */
export interface Claim {
  /** Name at the time of assertion.  For humans; the hash is what identifies. */
  decl: string
  hash: string
  /** Which hasher produced it.  Hashes from different hashers never compare. */
  hasher: string
  repo: string
  commit: string
  toolchain: string
  /** RFC 3339, UTC. */
  asserted: string
  note: string
}

export interface Certificate {
  claim: Claim
  /** GitHub login of the issuer, as attested by this server. */
  issuer: string
  /** Armored detached OpenPGP signature over the canonical claim, if signed. */
  signature?: string
  /** Fingerprint of the key the signature was made with. */
  fingerprint?: string
}

/** Whether a certificate carries proof, or only this server's word for it. */
export type Assurance = 'signed' | 'attested' | 'invalid'

/**
 * A withdrawal, signed by the key that made the assertion.
 *
 * A `revoked_at` column is a fact about one database.  Once a certificate can
 * travel, its withdrawal has to travel too, and has to be exactly as checkable
 * as the assertion was — otherwise the cheapest attack on the network is to
 * tell everyone that somebody else's certificate was withdrawn.
 *
 * See §6 of FEDERATION.md.  A revocation suppresses the certificates with the
 * same `(fingerprint, hash, hasher)` whose `asserted` is not later than
 * `revoked`, so re-issuing afterwards reinstates without a second message.
 */
export interface Revocation {
  fingerprint: string
  hash: string
  hasher: string
  reason: string
  /** RFC 3339, UTC. */
  revoked: string
}

const CLAIM_FIELDS: (keyof Claim)[] = [
  'asserted',
  'commit',
  'decl',
  'hash',
  'hasher',
  'note',
  'repo',
  'toolchain',
]

/**
 * The exact bytes a signature is made over.
 *
 * Fields in a fixed order with no incidental whitespace, so that a claim
 * re-serialised anywhere — this server, the CLI, a reader checking by hand —
 * produces the identical string.  Anything less rigid and a signature would
 * verify on the machine that made it and nowhere else.
 */
export function canonicalClaim(claim: Claim): string {
  const parts = CLAIM_FIELDS.map((field) => `${JSON.stringify(field)}:${JSON.stringify(claim[field])}`)
  return `{${parts.join(',')}}`
}

/** Reject anything that is not a well-formed claim before it reaches the database. */
export function parseClaim(value: unknown): Claim | { error: string } {
  if (typeof value !== 'object' || value === null) return { error: 'claim must be an object' }
  const raw = value as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const field of CLAIM_FIELDS) {
    const got = raw[field]
    if (field === 'note') {
      out[field] = typeof got === 'string' ? got : ''
      continue
    }
    if (typeof got !== 'string' || got.length === 0) return { error: `claim.${field} is required` }
    out[field] = got
  }
  if (!/^[0-9a-f]{16,128}$/.test(out.hash)) {
    return { error: 'claim.hash must be lower-case hex' }
  }
  if (Number.isNaN(Date.parse(out.asserted))) return { error: 'claim.asserted must be a timestamp' }
  return out as unknown as Claim
}

const REVOCATION_FIELDS: (keyof Revocation)[] = [
  'fingerprint',
  'hash',
  'hasher',
  'reason',
  'revoked',
]

/** The bytes a revocation's signature covers.  Same rules as `canonicalClaim`. */
export function canonicalRevocation(revocation: Revocation): string {
  const parts = REVOCATION_FIELDS.map(
    (field) => `${JSON.stringify(field)}:${JSON.stringify(revocation[field])}`,
  )
  return `{${parts.join(',')}}`
}

export function parseRevocation(value: unknown): Revocation | { error: string } {
  if (typeof value !== 'object' || value === null) return { error: 'revocation must be an object' }
  const raw = value as Record<string, unknown>
  const out: Record<string, string> = {}
  for (const field of REVOCATION_FIELDS) {
    const got = raw[field]
    if (field === 'reason') {
      out[field] = typeof got === 'string' ? got : ''
      continue
    }
    if (typeof got !== 'string' || got.length === 0) return { error: `revocation.${field} is required` }
    out[field] = got
  }
  if (!/^[0-9a-f]{16,128}$/.test(out.hash)) return { error: 'revocation.hash must be lower-case hex' }
  if (!/^[0-9a-fA-F]{16,64}$/.test(out.fingerprint)) {
    return { error: 'revocation.fingerprint must be hex' }
  }
  out.fingerprint = out.fingerprint.toLowerCase()
  if (Number.isNaN(Date.parse(out.revoked))) return { error: 'revocation.revoked must be a timestamp' }
  return out as unknown as Revocation
}

export interface Verdict {
  ok: boolean
  /** Fingerprint of the key that actually made the signature. */
  fingerprint?: string
  reason?: string
}

/**
 * Check a detached signature over `text` against a set of public keys.
 *
 * The server does this so it can store the verdict and answer "who trusts
 * this" quickly — but it stores it as a *cache*, and hands back everything a
 * client needs to repeat the check itself.  A tool whose subject is trust
 * should not ask to be taken at its word, and a compromised server that can
 * fabricate `attested` rows still cannot forge one of these.
 *
 * The signing key has to be *identified*, not merely present: openpgp will
 * confirm a signature against a bundle without saying which key in it signed,
 * and a verdict that cannot name the key is useless for attributing anything.
 * So a signature whose key is not among those offered is a failure here, even
 * though the cryptography succeeded.
 */
export async function verifyDetached(
  text: string,
  armoredSignature: string,
  armoredKeys: string[],
): Promise<Verdict> {
  if (armoredKeys.length === 0) return { ok: false, reason: 'no public key to check against' }
  try {
    const message = await openpgp.createMessage({ text })
    const signature = await openpgp.readSignature({ armoredSignature })
    const keys = await Promise.all(armoredKeys.map((armoredKey) => openpgp.readKey({ armoredKey })))
    const result = await openpgp.verify({ message, signature, verificationKeys: keys })
    const check = result.signatures[0]
    if (!check) return { ok: false, reason: 'no signature found' }
    await check.verified
    const keyID = check.keyID.toHex()
    const key = keys.find((candidate) =>
      candidate.getKeys().some((sub) => sub.getKeyID().toHex() === keyID),
    )
    if (!key) return { ok: false, reason: 'signature is not from any of the offered keys' }
    return { ok: true, fingerprint: key.getFingerprint().toLowerCase() }
  } catch (error) {
    return { ok: false, reason: String(error instanceof Error ? error.message : error) }
  }
}

export function verifySignature(
  claim: Claim,
  armoredSignature: string,
  armoredKeys: string[],
): Promise<Verdict> {
  return verifyDetached(canonicalClaim(claim), armoredSignature, armoredKeys)
}

/**
 * Read an armored public key, refusing a private one.
 *
 * A private key block parses perfectly well as a key, so "it loaded" is not the
 * check.  Nothing in this server has any use for signing material, and the way
 * to guarantee it never leaks it is to never hold it.
 */
export async function readPublicKey(
  armored: string,
): Promise<{ fingerprint: string } | { error: string }> {
  if (typeof armored !== 'string') return { error: 'expected an armored PGP public key' }
  // Checked before the public-key check so that someone who pastes the wrong
  // half is told what they actually did, rather than that it is not a key.
  if (armored.includes('PRIVATE KEY BLOCK')) {
    return { error: 'that is a private key — never send one here' }
  }
  if (!armored.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    return { error: 'expected an armored PGP public key' }
  }
  try {
    const key = await openpgp.readKey({ armoredKey: armored })
    if (key.isPrivate()) return { error: 'that is a private key — never send one here' }
    return { fingerprint: key.getFingerprint().toLowerCase() }
  } catch (error) {
    return { error: `unreadable key: ${String(error instanceof Error ? error.message : error)}` }
  }
}
