import { useEffect, useState } from 'react'
import {
  followIdentity,
  followKey,
  hasServer,
  signInUrl,
  unfollowIdentity,
  unfollowKey,
  verifyHere,
  whoTrusts,
  type Answer,
  type Certificate,
  type Identity,
} from '../data/certificates'
import type { Decl, IndexMeta } from '../data/types'
import { TrustThis } from './TrustThis'

interface WhoTrustsProps {
  decl: Decl
  meta: IndexMeta
  hasher: string
  identity: Identity | null
  following: Set<string>
  /** Fingerprints of keys you follow, which is the portable form. */
  followingKeys: Set<string>
  onFollowingChange: () => void
}

type Checked = { ok: true } | { ok: false; reason: string }

/**
 * Who else vouches for this declaration.
 *
 * Certificates are keyed by semantic hash, so these are people who vouched for
 * *this content* — possibly under another name, in another repository, at
 * another commit.  That is the point of hashing rather than naming: a review
 * done once keeps applying for as long as the meaning holds.
 *
 * Some of them will not have been written on the server being read.  Those are
 * labelled with where they came from, and can be checked here in the page,
 * because a certificate relayed by a stranger is worth exactly its signature
 * and nothing else.
 */
export function WhoTrusts({
  decl,
  meta,
  hasher,
  identity,
  following,
  followingKeys,
  onFollowingChange,
}: WhoTrustsProps) {
  const [answer, setAnswer] = useState<Answer | null>(null)
  const [busy, setBusy] = useState(false)
  const [reloads, setReloads] = useState(0)
  const [checked, setChecked] = useState<Record<string, Checked>>({})

  useEffect(() => {
    if (!hasServer() || !decl.hash) {
      setAnswer({ certificates: [], truncated: false, askedPeers: 0 })
      return
    }
    let current = true
    setAnswer(null)
    setChecked({})
    whoTrusts(decl.hash, hasher).then((found) => {
      if (current) setAnswer(found)
    })
    return () => {
      current = false
    }
  }, [decl.hash, hasher, reloads])

  if (!hasServer()) return null

  if (!decl.hash) {
    return (
      <section className="who-trusts">
        <h3>Who trusts this</h3>
        <p className="who-trusts-empty">
          This index carries no semantic hashes, so certificates cannot be matched to it. Re-export
          with <code>--with-hashes</code>.
        </p>
      </section>
    )
  }

  const certificates = answer?.certificates ?? null

  const toggleLogin = async (login: string) => {
    setBusy(true)
    if (following.has(login)) await unfollowIdentity(login)
    else await followIdentity(login)
    onFollowingChange()
    setBusy(false)
  }

  const toggleKey = async (fingerprint: string, label: string) => {
    setBusy(true)
    if (followingKeys.has(fingerprint)) await unfollowKey(fingerprint)
    else await followKey(fingerprint, label)
    onFollowingChange()
    setBusy(false)
  }

  const check = async (id: string, certificate: Certificate) => {
    const result = await verifyHere(certificate)
    setChecked((previous) => ({
      ...previous,
      [id]: result.ok ? { ok: true } : { ok: false, reason: result.reason },
    }))
  }

  return (
    <section className="who-trusts">
      <div className="who-trusts-head">
        <h3>Who trusts this</h3>
        <span className="who-trusts-hash" title="The semantic hash certificates are keyed by">
          {decl.hash}
        </span>
        {!identity && (
          <a className="who-trusts-signin" href={signInUrl()}>
            sign in with GitHub
          </a>
        )}
      </div>

      {identity && (
        <TrustThis
          decl={decl}
          meta={meta}
          mine={(certificates ?? []).some((c) => c.provenance.local && c.issuer === identity.login)}
          busy={busy}
          onPublished={() => {
            setReloads((n) => n + 1)
            onFollowingChange()
          }}
        />
      )}

      {certificates === null && <p className="who-trusts-empty">Looking…</p>}
      {certificates?.length === 0 && (
        <p className="who-trusts-empty">Nobody has published a certificate for this content yet.</p>
      )}

      {certificates?.map((certificate) => {
        const id = `${certificate.fingerprint ?? certificate.issuer}-${certificate.claim.hash}`
        const verdict = checked[id]
        const followed = certificate.fingerprint
          ? followingKeys.has(certificate.fingerprint)
          : following.has(certificate.issuer)
        return (
          <div className="certificate" key={id}>
            <span className="certificate-issuer">
              {certificate.issuer || certificate.fingerprint?.slice(-16) || 'unknown'}
            </span>
            <span
              className={`certificate-assurance ${certificate.assurance}`}
              title={
                certificate.assurance === 'signed'
                  ? `Signed with key ${certificate.fingerprint ?? ''}, tied to the account via ${
                      certificate.keyVerifiedVia ?? 'self'
                    }.`
                  : 'Asserted by a signed-in account, on the server’s word alone — not signed.'
              }
            >
              {certificate.assurance}
              {certificate.assurance === 'signed' && certificate.keyVerifiedVia === 'github' && ' ✓'}
            </span>

            {!certificate.provenance.local && (
              <span
                className="certificate-relayed"
                title={
                  `Relayed from ${certificate.provenance.origin || 'another node'}` +
                  (certificate.provenance.fromPeer
                    ? ` via ${certificate.provenance.fromPeer}`
                    : '') +
                  '. The server checked its signature; you can check it again here.'
                }
              >
                relayed
              </span>
            )}

            {certificate.claim.note && (
              <span className="certificate-note">{certificate.claim.note}</span>
            )}
            <span
              className="certificate-where"
              title={`${certificate.claim.repo} @ ${certificate.claim.commit}`}
            >
              {certificate.claim.repo} @ {certificate.claim.commit.slice(0, 9)}
            </span>

            {certificate.signature && certificate.key && (
              <button
                className={`certificate-check${verdict ? (verdict.ok ? ' good' : ' bad') : ''}`}
                title={
                  verdict
                    ? verdict.ok
                      ? 'Checked in this page, against the key that travelled with it.'
                      : verdict.reason
                    : 'Check this signature here, rather than taking the server’s word for it.'
                }
                onClick={() => void check(id, certificate)}
              >
                {verdict ? (verdict.ok ? 'checked here ✓' : 'does not verify') : 'check it yourself'}
              </button>
            )}

            {identity && certificate.issuer !== identity.login && (
              <button
                className="certificate-follow"
                disabled={busy}
                onClick={() =>
                  certificate.fingerprint
                    ? void toggleKey(certificate.fingerprint, certificate.issuer)
                    : void toggleLogin(certificate.issuer)
                }
                title={
                  certificate.fingerprint
                    ? 'Follow this key. A key means the same thing on every node; a name does not.'
                    : 'Follow this account on this server.'
                }
              >
                {followed ? 'unfollow' : 'trust their certificates'}
              </button>
            )}
          </div>
        )
      })}

      {answer?.truncated && (
        <p className="who-trusts-truncated">
          One of this server’s peers did not answer in time, so this list may be short. It is not a
          statement that nobody else vouches for this.
        </p>
      )}
    </section>
  )
}
