import { useState } from 'react'
import { followIdentity, signInUrl, unfollowIdentity, type Identity } from '../data/certificates'

interface FollowPanelProps {
  identity: Identity | null
  /** GitHub logins whose certificates already count as your own. */
  following: Set<string>
  /** How many declarations that adds up to, across everyone followed. */
  federatedCount: number
  onChange: () => void
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
export function FollowPanel({ identity, following, federatedCount, onChange }: FollowPanelProps) {
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
    const result = await followIdentity(wanted)
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
          placeholder="GitHub login"
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

      <p className="follows-note">
        Their certificates behave as if you had marked the declarations trusted yourself. This is
        one hop only: it does not extend to whoever they trust in turn.
      </p>
    </section>
  )
}
