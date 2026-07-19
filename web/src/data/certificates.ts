/**
 * The certificate server, as the browser sees it.
 *
 * Everything here treats the server as a place to *find* assertions, never as
 * the thing that makes them true.  Certificates come back with the canonical
 * bytes that were signed, so a reader can check a signature independently; the
 * `assurance` field is the server's opinion and is labelled as such in the UI.
 */

export interface Certificate {
  issuer: string
  avatarUrl: string
  decl: string
  hash: string
  hasher: string
  repo: string
  commit: string
  toolchain: string
  asserted: string
  note: string
  signature: string | null
  fingerprint: string | null
  /** `signed` carries a verified signature; `attested` is the server's word. */
  assurance: 'signed' | 'attested'
  /** How the signing key was tied to the account: `github` or `self`. */
  keyVerifiedVia: string | null
  /** Exactly what was signed, so the check can be repeated here. */
  canonical: string
}

/** The part of a certificate that gets signed. */
export interface Claim {
  decl: string
  hash: string
  hasher: string
  repo: string
  commit: string
  toolchain: string
  asserted: string
  note: string
}

const CLAIM_FIELDS: (keyof Claim)[] = [
  'asserted', 'commit', 'decl', 'hash', 'hasher', 'note', 'repo', 'toolchain',
]

/**
 * The exact bytes a signature covers.
 *
 * The same eight fields in the same order as `server/src/certificate.ts` and
 * `Trust/Cert.lean`.  Three implementations of this exist because the claim is
 * built in three places; they are only worth anything if they agree byte for
 * byte, which `certificates.test.ts` pins against a vector produced by the Lean
 * one.
 */
export function canonicalClaim(claim: Claim): string {
  return `{${CLAIM_FIELDS.map(
    (field) => `${JSON.stringify(field)}:${JSON.stringify(claim[field])}`,
  ).join(',')}}`
}

export interface Identity {
  login: string
  avatarUrl: string
}

/** Where the server lives; unset means the federation features stay hidden. */
export const SERVER =
  ((import.meta as unknown as { env?: Record<string, string | undefined> }).env
    ?.VITE_TRUST_SERVER ?? '')

async function call<T>(path: string, init?: RequestInit): Promise<T | null> {
  if (!SERVER) return null
  try {
    const response = await fetch(`${SERVER}${path}`, {
      ...init,
      // The session is a cookie on the server's origin, so it has to be sent.
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    })
    if (!response.ok) return null
    return (await response.json()) as T
  } catch {
    // The server being down must never stop the index from being readable.
    return null
  }
}

export async function whoTrusts(hash: string, hasher: string): Promise<Certificate[]> {
  const query = new URLSearchParams({ hash, hasher })
  const result = await call<{ certificates: Certificate[] }>(`/api/certificates?${query}`)
  return result?.certificates ?? []
}

export async function currentIdentity(): Promise<Identity | null> {
  const result = await call<{ user: { login: string } | null }>('/api/me')
  return result?.user ? { login: result.user.login, avatarUrl: '' } : null
}

export async function trustList(): Promise<Identity[]> {
  const result = await call<{ trusted: Identity[] }>('/api/trust-list')
  return result?.trusted ?? []
}

export async function followIdentity(login: string): Promise<boolean> {
  return (await call(`/api/trust-list/${encodeURIComponent(login)}`, { method: 'POST' })) !== null
}

export async function unfollowIdentity(login: string): Promise<boolean> {
  return (await call(`/api/trust-list/${encodeURIComponent(login)}`, { method: 'DELETE' })) !== null
}

/**
 * Every hash the people you follow vouch for.
 *
 * One flat set, which is all the views need: `trustedCutSource` already turns
 * "these declarations are trusted" into graph semantics, so federated trust
 * only has to widen the set rather than teach anything new.
 */
export async function trustedHashes(hasher: string): Promise<Set<string>> {
  const result = await call<{ hashes: { hash: string }[] }>(
    `/api/trusted?${new URLSearchParams({ hasher })}`,
  )
  return new Set((result?.hashes ?? []).map((row) => row.hash))
}

/**
 * Publish a certificate.
 *
 * Unsigned unless a signature is supplied — which is the ordinary case, and
 * what the server records as `attested`.
 */
export async function publish(claim: Claim, signature?: string): Promise<string | null> {
  const result = await call<{ assurance: string }>('/api/certificates', {
    method: 'POST',
    body: JSON.stringify({ claim, signature }),
  })
  return result?.assurance ?? null
}

export async function revoke(hash: string): Promise<boolean> {
  return (await call(`/api/certificates/${encodeURIComponent(hash)}`, { method: 'DELETE' })) !== null
}

/**
 * Sign a claim here, in the page, with a key the reader supplies.
 *
 * The key never goes to the server — but it does enter this page's memory,
 * which is a weaker guarantee than the command line gives, where it stays
 * inside `gpg-agent` and `trust` never sees it.  Anything able to run script
 * on this page could take it while it is here.  So: nothing is persisted, the
 * armoured text is dropped as soon as the signature exists, and the UI says all
 * of this rather than implying the two paths are equivalent.
 *
 * `openpgp` is imported only when someone actually signs, so a reader who never
 * does pays nothing for it.
 */
export async function signInBrowser(
  claim: Claim,
  armoredPrivateKey: string,
  passphrase: string,
): Promise<{ signature: string; publicKey: string } | { error: string }> {
  try {
    const openpgp = await import('openpgp')
    const encrypted = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey })
    const key = encrypted.isDecrypted()
      ? encrypted
      : await openpgp.decryptKey({ privateKey: encrypted, passphrase })
    const signature = await openpgp.sign({
      message: await openpgp.createMessage({ text: canonicalClaim(claim) }),
      signingKeys: key,
      detached: true,
      format: 'armored',
    })
    // The public half goes up so the server can check this and later signatures;
    // the private half stays here and is dropped by the caller.
    return { signature: signature as string, publicKey: key.toPublic().armor() }
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) }
  }
}

/** Register the public half of a signing key. */
export async function registerPublicKey(armored: string): Promise<boolean> {
  return (await call('/api/keys', { method: 'POST', body: JSON.stringify({ armored }) })) !== null
}

export function signInUrl(): string {
  return `${SERVER}/auth/github`
}
