import { useEffect, useState } from 'react'
import {
  SERVER,
  followIdentity,
  signInUrl,
  unfollowIdentity,
  whoTrusts,
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
  onFollowingChange: () => void
}

/**
 * Who else vouches for this declaration.
 *
 * Certificates are keyed by semantic hash, so these are people who vouched for
 * *this content* — possibly under another name, in another repository, at
 * another commit.  That is the point of hashing rather than naming: a review
 * done once keeps applying for as long as the meaning holds.
 */
export function WhoTrusts({
  decl,
  meta,
  hasher,
  identity,
  following,
  onFollowingChange,
}: WhoTrustsProps) {
  const [certificates, setCertificates] = useState<Certificate[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [reloads, setReloads] = useState(0)

  useEffect(() => {
    if (!SERVER || !decl.hash) {
      setCertificates([])
      return
    }
    let current = true
    setCertificates(null)
    whoTrusts(decl.hash, hasher).then((found) => {
      if (current) setCertificates(found)
    })
    return () => {
      current = false
    }
  }, [decl.hash, hasher, reloads])

  if (!SERVER) return null

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

  const toggle = async (login: string) => {
    setBusy(true)
    if (following.has(login)) await unfollowIdentity(login)
    else await followIdentity(login)
    onFollowingChange()
    setBusy(false)
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
          mine={(certificates ?? []).some((c) => c.issuer === identity.login)}
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

      {certificates?.map((certificate) => (
        <div className="certificate" key={`${certificate.issuer}-${certificate.hash}`}>
          <span className="certificate-issuer">{certificate.issuer}</span>
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
          {certificate.note && <span className="certificate-note">{certificate.note}</span>}
          <span className="certificate-where" title={`${certificate.repo} @ ${certificate.commit}`}>
            {certificate.repo} @ {certificate.commit.slice(0, 9)}
          </span>
          {identity && certificate.issuer !== identity.login && (
            <button className="certificate-follow" disabled={busy} onClick={() => toggle(certificate.issuer)}>
              {following.has(certificate.issuer) ? 'unfollow' : 'trust their certificates'}
            </button>
          )}
        </div>
      ))}
    </section>
  )
}
