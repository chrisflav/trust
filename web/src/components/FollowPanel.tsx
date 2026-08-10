import { useState } from 'react'
import {
  followIdentity,
  followKey,
  signInUrl,
  unfollowIdentity,
  unfollowKey,
  type FollowedKey,
  type Identity,
} from '../data/certificates'

interface FollowPanelProps {
  identity: Identity | null
  /** GitHub logins whose certificates already count as your own. */
  following: Set<string>
  /** Keys whose certificates count, wherever they were published. */
  followingKeys: FollowedKey[]
  /** How many declarations that adds up to, across everyone followed. */
  federatedCount: number
  onChange: () => void
}

/** A fingerprint, rather than a name: hex, and far too long to be a login. */
function looksLikeFingerprint(value: string): boolean {
  return /^[0-9a-fA-F]{16,64}$/.test(value.replace(/\s/g, ''))
}

/**
 * Who you trust, as a list you can edit.
 *
 * The per-declaration "trust their certificates" button only ever offers the
 * people who certified the declaration in front of you, which makes following
 * somebody depend on already having found their work.  This is the other half:
 * add by name, see everyone at once, and drop them again.
 *
 * Following is one hop and never transitive — the server joins a single level,
 * so trusting somebody does not quietly enrol the people *they* trust.  The
 * panel says so, because an intuition that trust flows onwards is easy to form
 * and would be wrong.
 */
export function FollowPanel({
  identity,
  following,
  followingKeys,
  federatedCount,
  onChange,
}: FollowPanelProps) {
  const [login, setLogin] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!identity) {
    return (
      <section className="follows">
        <div className="follows-head">
          <h3>People you trust</h3>
        </div>
        <p className="follows-empty">
          <a href={signInUrl()}>Sign in with GitHub</a> to follow people, and their certificates
          will count as your own trust marks.
        </p>
      </section>
    )
  }

  const add = async () => {
    const wanted = login.trim().replace(/^@/, '')
    if (!wanted) return
    setBusy(true)
    setError(null)
    // A fingerprint and a login are told apart by shape rather than by a mode
    // switch: they are the same intention, and which one you have to hand
    // depends only on whether you met the person or their signature.
    const result = looksLikeFingerprint(wanted)
      ? await followKey(wanted.replace(/\s/g, '').toLowerCase(), '')
      : await followIdentity(wanted)
    setBusy(false)
    if (!result.ok) {
      setError(result.error ?? 'could not follow them')
      return
    }
    setLogin('')
    onChange()
  }

  const drop = async (who: string) => {
    setBusy(true)
    setError(null)
    await unfollowIdentity(who)
    setBusy(false)
    onChange()
  }

  const dropKey = async (fingerprint: string) => {
    setBusy(true)
    setError(null)
    await unfollowKey(fingerprint)
    setBusy(false)
    onChange()
  }

  const followed = [...following].sort()

  return (
    <section className="follows">
      <div className="follows-head">
        <h3>People you trust</h3>
        <span className="follows-count">
          {followed.length === 0
            ? 'nobody yet'
            : `${followed.length} · ${federatedCount.toLocaleString()} declaration${
                federatedCount === 1 ? '' : 's'
              } trusted through them`}
        </span>
      </div>

      <div className="follows-add">
        <input
          className="follows-input"
          value={login}
          placeholder="GitHub login, or a key fingerprint"
          spellCheck={false}
          autoComplete="off"
          disabled={busy}
          onChange={(event) => setLogin(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') void add()
          }}
        />
        <button disabled={busy || login.trim().length === 0} onClick={() => void add()}>
          follow
        </button>
      </div>

      {error && <p className="follows-error">{error}</p>}

      {followed.length > 0 && (
        <ul className="follows-list">
          {followed.map((who) => (
            <li key={who}>
              <span className="follows-login">{who}</span>
              <button className="follows-drop" disabled={busy} onClick={() => void drop(who)}>
                unfollow
              </button>
            </li>
          ))}
        </ul>
      )}

      {followingKeys.length > 0 && (
        <ul className="follows-list follows-keys">
          {followingKeys.map((key) => (
            <li key={key.fingerprint}>
              <span className="follows-login" title={key.fingerprint}>
                {key.label || `key ${key.fingerprint.slice(-16)}`}
              </span>
              <button
                className="follows-drop"
                disabled={busy}
                onClick={() => void dropKey(key.fingerprint)}
              >
                unfollow
              </button>
            </li>
          ))}
        </ul>
      )}

      <p className="follows-note">
        Their certificates behave as if you had marked the declarations trusted yourself. This is
        one hop only: it does not extend to whoever they trust in turn.
      </p>
      <p className="follows-note">
        Following a <em>key</em> rather than a name is what keeps working when a certificate reaches
        this server from another one: a login means something only where it was issued, and a
        signature means the same thing everywhere.
      </p>
    </section>
  )
}
