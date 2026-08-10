/**
 * The certificate server, as the browser sees it.
 *
 * Everything here treats the server as a place to *find* assertions, never as
 * the thing that makes them true.  Certificates come back with the canonical
 * bytes that were signed, so a reader can check a signature independently; the
 * `assurance` field is the server's opinion and is labelled as such in the UI.
 */

/** Where a certificate came from, and how much of that this node checked. */
export interface Provenance {
  /** Issued on the server being read, rather than relayed to it. */
  local: boolean
  /** The node that originated it, as it says of itself.  Unverified. */
  origin: string
  /** The peer it arrived through. */
  fromPeer: string
  /** That the server applied the acceptance rules.  Its word, not proof. */
  verifiedHere: boolean
  fetchedAt: string | null
}

export interface Certificate {
  claim: Claim
  issuer: string
  avatarUrl: string
  signature: string | null
  fingerprint: string | null
  /** The public key, when one travelled with it — what lets us check it here. */
  key: string | null
  /** `signed` carries a verified signature; `attested` is the server's word. */
  assurance: 'signed' | 'attested'
  /** How the signing key was tied to the account: `github`, `self` or `remote`. */
  keyVerifiedVia: string | null
  /** Exactly what was signed, so the check can be repeated here. */
  canonical: string
  provenance: Provenance
}

export interface Answer {
  certificates: Certificate[]
  /**
   * The answer may be short: a peer did not reply in time.
   *
   * Worth surfacing, because "nobody vouches for this" and "I could not find
   * out" are different sentences and only one of them is a reason to worry.
   */
  truncated: boolean
  askedPeers: number
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
  /** A local database has one user and no sign-in; the UI says so rather than
   *  offering an OAuth flow that does not exist there. */
  local?: boolean
}

/** The server baked in at build time, which is only the starting point. */
export const DEFAULT_SERVER =
  ((import.meta as unknown as { env?: Record<string, string | undefined> }).env
    ?.VITE_TRUST_SERVER ?? '')

const SERVER_KEY = 'trust:server'

/**
 * Which node this page talks to.
 *
 * Chosen at runtime rather than baked in, because there is no longer one
 * server: a reader may keep their own database on their laptop, or read a
 * colleague's, and rebuilding the frontend to point somewhere else is not a
 * thing anyone should have to do.
 *
 * One node at a time, deliberately.  The session is a first-party cookie on
 * that node's origin, and asking the browser to hold credentialled sessions for
 * several origins at once is a fight with third-party cookie policy that would
 * be lost.  Reaching other nodes is the *server's* job — it federates on your
 * behalf, which is the whole design.
 */
export function serverUrl(): string {
  try {
    return localStorage.getItem(SERVER_KEY) || DEFAULT_SERVER
  } catch {
    // Private mode: the default is still perfectly usable.
    return DEFAULT_SERVER
  }
}

export function setServerUrl(url: string): void {
  try {
    const trimmed = url.trim().replace(/\/+$/, '')
    if (trimmed && trimmed !== DEFAULT_SERVER) localStorage.setItem(SERVER_KEY, trimmed)
    else localStorage.removeItem(SERVER_KEY)
  } catch {
    /* nothing to do; the choice simply does not persist */
  }
}

/** Whether there is a server at all.  Unset hides the federation features. */
export function hasServer(): boolean {
  return serverUrl().length > 0
}

async function call<T>(path: string, init?: RequestInit): Promise<T | null> {
  const SERVER = serverUrl()
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

/**
 * Who vouches for this content, here and anywhere the server can reach.
 *
 * The server fans out to its peers; this asks one question and gets one answer,
 * with each certificate labelled by where it came from.
 */
export async function whoTrusts(hash: string, hasher: string): Promise<Answer> {
  const query = new URLSearchParams({ hash, hasher })
  const result = await call<Answer>(`/api/certificates?${query}`)
  return result ?? { certificates: [], truncated: false, askedPeers: 0 }
}

/**
 * Check a certificate's signature in this page, against the key it carries.
 *
 * The server already did this and says so in `assurance` — but that is the
 * server's word, and the subject here is trust.  Doing it again locally is the
 * difference between "a server told me this is signed" and "I watched the
 * signature verify", and the second is the only one worth anything if the
 * server is the thing you are unsure about.
 *
 * `openpgp` is imported only when someone actually checks, so a reader who
 * never does pays nothing for it.
 */
export async function verifyHere(
  certificate: Certificate,
): Promise<{ ok: true; fingerprint: string } | { ok: false; reason: string }> {
  if (!certificate.signature) return { ok: false, reason: 'this certificate is not signed' }
  if (!certificate.key) {
    return { ok: false, reason: 'the server did not hand over the public key to check it against' }
  }
  // The bytes are recomputed from the claim rather than taken from `canonical`:
  // checking the server's own rendering against the server's own signature
  // would verify nothing about the claim being displayed.
  const bytes = canonicalClaim(certificate.claim)
  try {
    const openpgp = await import('openpgp')
    const key = await openpgp.readKey({ armoredKey: certificate.key })
    if (certificate.fingerprint && key.getFingerprint().toLowerCase() !== certificate.fingerprint) {
      return { ok: false, reason: 'the key does not match the fingerprint claimed' }
    }
    const result = await openpgp.verify({
      message: await openpgp.createMessage({ text: bytes }),
      signature: await openpgp.readSignature({ armoredSignature: certificate.signature }),
      verificationKeys: key,
    })
    const check = result.signatures[0]
    if (!check) return { ok: false, reason: 'no signature found' }
    await check.verified
    const keyID = check.keyID.toHex()
    if (!key.getKeys().some((sub) => sub.getKeyID().toHex() === keyID)) {
      return { ok: false, reason: 'signed by a key other than the one it carries' }
    }
    return { ok: true, fingerprint: key.getFingerprint().toLowerCase() }
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) }
  }
}

export async function currentIdentity(): Promise<Identity | null> {
  const result = await call<{ user: { login: string } | null; local?: boolean }>('/api/me')
  return result?.user
    ? { login: result.user.login, avatarUrl: '', local: result.local === true }
    : null
}

/** A key you follow, with whatever name you gave it. */
export interface FollowedKey {
  fingerprint: string
  label: string
}

export async function trustList(): Promise<{ people: Identity[]; keys: FollowedKey[] }> {
  const result = await call<{ trusted: Identity[]; keys: FollowedKey[] }>('/api/trust-list')
  return { people: result?.trusted ?? [], keys: result?.keys ?? [] }
}

/**
 * Follow a key.
 *
 * The portable half of a trust list.  A login means something only on the
 * server that issued it; a certificate relayed from three nodes away carries a
 * fingerprint and little else you could have checked, so following the key is
 * the form that keeps working as things travel.
 */
export async function followKey(fingerprint: string, label: string): Promise<{ ok: boolean; error?: string }> {
  const SERVER = serverUrl()
  if (!SERVER) return { ok: false, error: 'no certificate server is configured' }
  try {
    const response = await fetch(`${SERVER}/api/trust-keys/${encodeURIComponent(fingerprint)}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label }),
    })
    if (response.ok) return { ok: true }
    const body = (await response.json().catch(() => null)) as { error?: string } | null
    return { ok: false, error: body?.error ?? `the server said ${response.status}` }
  } catch {
    return { ok: false, error: 'could not reach the certificate server' }
  }
}

export async function unfollowKey(fingerprint: string): Promise<boolean> {
  return (await call(`/api/trust-keys/${encodeURIComponent(fingerprint)}`, { method: 'DELETE' })) !== null
}

/** What the server says it is, and how far it can see. */
export interface NodeDescriptor {
  protocol: string
  url: string
  name: string
  software?: string
  counts?: { certificates?: number; peers?: number }
}

export async function describeServer(): Promise<NodeDescriptor | null> {
  return call<NodeDescriptor>('/api/federation')
}

/**
 * Follow somebody, reporting *why* it failed.
 *
 * Following by hand is the one place a person types a name from memory, so
 * "nobody here by that name" and "the server is not answering" have to be told
 * apart — they call for completely different reactions, and `call` collapses
 * both to null.
 */
export async function followIdentity(login: string): Promise<{ ok: boolean; error?: string }> {
  const SERVER = serverUrl()
  if (!SERVER) return { ok: false, error: 'no certificate server is configured' }
  try {
    const response = await fetch(`${SERVER}/api/trust-list/${encodeURIComponent(login)}`, {
      method: 'POST',
      credentials: 'include',
    })
    if (response.ok) return { ok: true }
    const body = (await response.json().catch(() => null)) as { error?: string } | null
    return { ok: false, error: body?.error ?? `the server said ${response.status}` }
  } catch {
    return { ok: false, error: 'could not reach the certificate server' }
  }
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
  return `${serverUrl()}/auth/github`
}
