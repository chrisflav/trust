import { useEffect, useState } from 'react'
import {
  DEFAULT_SERVER,
  describeServer,
  serverUrl,
  setServerUrl,
  type NodeDescriptor,
} from '../data/certificates'

/**
 * Which trust database this page is reading.
 *
 * There is no longer one server, so which one you are looking at is a fact
 * worth showing rather than a build-time constant: a reader may keep their own
 * database locally, read a colleague's, or read a public one, and the answers
 * differ — not because the certificates differ, but because whose certificates
 * a node has heard of does.
 *
 * The node is asked to describe itself, and what it says about its own name is
 * shown as what it is: its own account of itself.  Nothing here is a trust
 * signal; the signatures are.
 */
export function ServerPicker() {
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(serverUrl())
  const [descriptor, setDescriptor] = useState<NodeDescriptor | null>(null)
  const [unreachable, setUnreachable] = useState(false)

  useEffect(() => {
    let current = true
    describeServer().then((found) => {
      if (!current) return
      setDescriptor(found)
      setUnreachable(found === null)
    })
    return () => {
      current = false
    }
  }, [])

  const apply = (next: string) => {
    setServerUrl(next)
    // A full reload rather than re-running every effect by hand.  Almost all
    // of this page's state — who you are, whose keys you follow, what counts as
    // trusted — is *about* the server, so keeping any of it across a change
    // would be showing one node's answers under another node's name.
    window.location.reload()
  }

  if (editing) {
    return (
      <div className="server-picker editing">
        <input
          className="server-input"
          value={value}
          spellCheck={false}
          autoComplete="off"
          placeholder="https://trust.example.org"
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') apply(value)
            if (event.key === 'Escape') setEditing(false)
          }}
        />
        <button onClick={() => apply(value)}>use</button>
        {serverUrl() !== DEFAULT_SERVER && DEFAULT_SERVER && (
          <button className="server-reset" onClick={() => apply(DEFAULT_SERVER)}>
            reset
          </button>
        )}
        <button className="server-cancel" onClick={() => setEditing(false)}>
          cancel
        </button>
      </div>
    )
  }

  const host = (() => {
    try {
      return new URL(serverUrl()).host
    } catch {
      return serverUrl()
    }
  })()

  return (
    <button
      className={`server-picker${unreachable ? ' unreachable' : ''}`}
      onClick={() => {
        setValue(serverUrl())
        setEditing(true)
      }}
      title={
        unreachable
          ? `${serverUrl()} is not answering`
          : `Reading ${serverUrl()}${
              descriptor?.counts?.peers
                ? `, which federates with ${descriptor.counts.peers} other node${
                    descriptor.counts.peers === 1 ? '' : 's'
                  }`
                : ''
            }. Click to read a different one.`
      }
    >
      <span className="server-name">{descriptor?.name ?? host}</span>
      {unreachable && <span className="server-warning">unreachable</span>}
      {!unreachable && descriptor?.counts?.peers ? (
        <span className="server-peers">+{descriptor.counts.peers}</span>
      ) : null}
    </button>
  )
}
