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

/**
 * Check a detached signature against the claim and a set of public keys.
 *
 * The server does this so it can store the verdict and answer "who trusts
 * this" quickly — but it stores it as a *cache*, and hands back everything a
 * client needs to repeat the check itself.  A tool whose subject is trust
 * should not ask to be taken at its word, and a compromised server that can
 * fabricate `attested` rows still cannot forge one of these.
 */
export async function verifySignature(
  claim: Claim,
  armoredSignature: string,
  armoredKeys: string[],
): Promise<{ ok: boolean; fingerprint?: string; reason?: string }> {
  if (armoredKeys.length === 0) return { ok: false, reason: 'issuer has no public key on file' }
  try {
    const message = await openpgp.createMessage({ text: canonicalClaim(claim) })
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
    return { ok: true, fingerprint: key?.getFingerprint() }
  } catch (error) {
    return { ok: false, reason: String(error instanceof Error ? error.message : error) }
  }
}
