import { useState } from 'react'
import {
  publish,
  registerPublicKey,
  revoke,
  signInBrowser,
  type Claim,
} from '../data/certificates'
import type { Decl, IndexMeta } from '../data/types'

interface TrustThisProps {
  decl: Decl
  meta: IndexMeta
  /** Whether you already have a live certificate for this content. */
  mine: boolean
  busy: boolean
  onPublished: () => void
}

/**
 * Declare a declaration trusted, and publish it.
 *
 * Signing is an optional extra rather than the price of entry: a certificate
 * from a signed-in account is already worth something, and requiring a key
 * would mean most declarations never get vouched for at all.  The signed
 * version says more, and the two are labelled differently everywhere they are
 * shown, so nobody has to guess which they are looking at.
 */
export function TrustThis({ decl, meta, mine, busy, onPublished }: TrustThisProps) {
  const [note, setNote] = useState('')
  const [signing, setSigning] = useState(false)
  const [privateKey, setPrivateKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [working, setWorking] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const claim = (): Claim => ({
    decl: decl.name,
    hash: decl.hash ?? '',
    hasher: meta.hasher ?? 'semantic-v1',
    repo: meta.repo,
    commit: meta.rev,
    toolchain: meta.toolchain,
    asserted: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    note,
  })

  const finish = (message: string | null) => {
    // Whatever happened, the key does not stay in this page a moment longer.
    setPrivateKey('')
    setPassphrase('')
    setWorking(false)
    setError(message)
    if (!message) {
      setNote('')
      setSigning(false)
      onPublished()
    }
  }

  const trustPlainly = async () => {
    setWorking(true)
    setError(null)
    finish((await publish(claim())) ? null : 'could not publish — are you still signed in?')
  }

  const trustSigned = async () => {
    setWorking(true)
    setError(null)
    const toSign = claim()
    const signed = await signInBrowser(toSign, privateKey, passphrase)
    if ('error' in signed) {
      finish(`could not sign: ${signed.error}`)
      return
    }
    // The public half has to be on file before the server can check the
    // signature, so it goes up first.
    if (!(await registerPublicKey(signed.publicKey))) {
      finish('signed, but the public key was rejected')
      return
    }
    finish((await publish(toSign, signed.signature)) ? null : 'signature did not verify server-side')
  }

  if (!decl.hash) return null

  if (mine) {
    return (
      <div className="trust-this">
        <span className="trust-this-mine">You vouch for this content.</span>
        <button
          disabled={busy || working}
          onClick={async () => {
            setWorking(true)
            await revoke(decl.hash!)
            finish(null)
          }}
        >
          withdraw
        </button>
      </div>
    )
  }

  return (
    <div className="trust-this">
      <input
        className="trust-this-note"
        value={note}
        placeholder="why do you trust it? (optional)"
        disabled={working}
        onChange={(event) => setNote(event.target.value)}
      />
      <button disabled={busy || working} onClick={() => void trustPlainly()}>
        trust this
      </button>
      <button
        className="trust-this-toggle"
        disabled={busy || working}
        onClick={() => setSigning(!signing)}
        title="Sign the assertion with an OpenPGP key, so it can be verified without trusting this server"
      >
        {signing ? 'cancel signing' : 'sign it too…'}
      </button>

      {signing && (
        <div className="trust-this-signing">
          <p className="trust-this-warning">
            Signing here is weaker than signing on the command line. Your key never reaches the
            server, but it does enter this page's memory, where anything able to run script here
            could take it. Nothing is stored, and the key is dropped the moment the signature
            exists — but for a key you care about, prefer{' '}
            <code>trust cert issue &amp;&amp; trust cert sign</code>, which leaves it inside{' '}
            <code>gpg-agent</code>. A dedicated signing subkey is a good idea either way.
          </p>
          <textarea
            className="trust-this-key"
            value={privateKey}
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
            spellCheck={false}
            autoComplete="off"
            disabled={working}
            onChange={(event) => setPrivateKey(event.target.value)}
          />
          <input
            className="trust-this-passphrase"
            type="password"
            value={passphrase}
            placeholder="passphrase, if the key has one"
            autoComplete="off"
            disabled={working}
            onChange={(event) => setPassphrase(event.target.value)}
          />
          <button disabled={working || privateKey.trim().length === 0} onClick={() => void trustSigned()}>
            sign and publish
          </button>
        </div>
      )}

      {error && <p className="trust-this-error">{error}</p>}
    </div>
  )
}
