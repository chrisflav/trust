# The trust federation protocol, version `trust/1`

A trust database holds certificates: assertions by one key-holder that one
declaration, identified by its semantic hash, is worth trusting.  This document
specifies how two such databases exchange them.

It is written as a protocol rather than as documentation of an implementation
because the point of federating is that the other end is not this code.  A node
that follows what is written here interoperates; a node that follows only what
`server/src` happens to do interoperates by luck.

## 1. What a node may claim

A node relays other people's assertions.  It is not a party to them, and the
protocol is built so that it cannot become one:

* **The signature is the assertion.**  Everything a receiving node believes
  about a federated entry, it believes because it checked a signature — never
  because the sending node said so.
* **A node has no authority over entries it did not originate.**  It cannot
  make one true, and the worst it can do is withhold one or fabricate an
  unsigned one, which is why unsigned entries do not federate (§3.1).
* **Identity across a boundary is a key fingerprint.**  A node can verify that
  key `F` signed some bytes.  It cannot verify that `F` belongs to the GitHub
  account `alice`, so any such binding travels as an unverified hint (§4.4) and
  must never be presented as fact.

The consequence worth stating plainly: federation widens *who you can hear
from*.  It does not widen *whom you trust*.  Trust remains a local decision
about specific keys, and no protocol message can change one node's trust list.

## 2. Node descriptor

```
GET /api/federation
```

```json
{
  "protocol": "trust/1",
  "url": "https://trust.example.org",
  "name": "example",
  "software": "trust-server/0.2.0",
  "policy": { "maxDepth": 2, "maxEntries": 500, "autodiscover": false },
  "counts": { "certificates": 1200, "peers": 3 }
}
```

`url` is the node's own canonical, externally reachable base URL.  A node that
is asked to add a peer **must** fetch this descriptor and check that `url`
matches the URL it was given (§5.2); without that check a node can be pointed
at any address on its own network and used as a probe.

`protocol` is the only field whose absence is fatal.  A receiver that does not
recognise the version must not proceed.

## 3. Entries

### 3.1 Only signed entries federate

The local server distinguishes two assurances: `signed`, an OpenPGP signature
verified against the issuer's key, and `attested`, meaning a signed-in account
asserted it and the server is vouching for that.

`attested` is a statement about the *server's* authentication, and it does not
survive being repeated by a third party: there is nothing for a receiver to
check, and a compromised or dishonest node can mint them freely.  So:

> A node **must not** export `attested` entries, and **must** discard any it
> receives.

This is a real restriction — it means unsigned certificates stay where they
were made — and it is the price of every federated entry being checkable.

### 3.2 The canonical bytes

A signature is made over `canonicalClaim`, defined identically in
`Trust/Cert.lean`, `server/src/certificate.ts` and `web/src/data/certificates.ts`:
the eight fields in alphabetical order, JSON-encoded with no incidental
whitespace.

```
{"asserted":"…","commit":"…","decl":"…","hash":"…","hasher":"…","note":"…","repo":"…","toolchain":"…"}
```

Escaping is `JSON.stringify`'s: the quote, the backslash, and the C0 controls
(`\b`, `\f`, `\n`, `\r`, `\t`, otherwise `\u00XX`).  Everything else, including
all non-ASCII, is emitted literally.  Three implementations agree on this byte
for byte, pinned by a shared vector in `certificates.test.ts`; a fourth must
match or its signatures verify nowhere.

### 3.3 Entry format

```json
{
  "claim":       { "asserted": "…", "commit": "…", "decl": "…", "hash": "…",
                   "hasher": "…", "note": "…", "repo": "…", "toolchain": "…" },
  "signature":   "-----BEGIN PGP SIGNATURE-----…",
  "key":         "-----BEGIN PGP PUBLIC KEY BLOCK-----…",
  "fingerprint": "…",
  "hints":       { "issuer": "alice", "keyVerifiedVia": "github",
                   "origin": "https://trust.example.org" }
}
```

The public key travels **with** the entry.  It costs a couple of kilobytes and
it is what makes the entry self-contained: a receiver can complete the check
without a second round trip to a key server it would then have to trust.

### 3.4 Acceptance rules

A receiver **must** apply all of the following, and **must** discard — never
store, never relay — an entry failing any of them:

1. `claim` parses: all eight fields present and strings, `hash` lower-case hex
   of 16–128 characters, `asserted` a parseable timestamp.
2. `key` is a readable OpenPGP **public** key.  Anything containing a private
   key block is discarded and its arrival is worth logging.
3. `fingerprint` equals the primary fingerprint of `key`, compared
   case-insensitively.
4. `signature` verifies over `canonicalClaim(claim)` against `key`.
5. The signing (sub)key belongs to `key`.  Verifying against a key bundle and
   then reporting the *primary* fingerprint without checking this would let an
   entry be attributed to a key that did not sign it.

Rule 5 is the one most easily got wrong, because most OpenPGP libraries will
happily tell you a signature is good without telling you which key in the
bundle made it.

### 3.5 Identity and replacement

An entry's identity is the triple `(fingerprint, hash, hasher)`.  Hashes from
different hashers are never comparable, so `hasher` is part of the key rather
than an attribute.

On collision the entry with the later `asserted` wins.  Ties are resolved by
keeping what is already stored, so that repeatedly gossiping the same set
converges instead of oscillating.

Replay is not an attack here and is not defended against: a signed entry says
what it says regardless of who repeats it, and the ability of anyone to carry
one to any node is exactly the property that makes the network work.

## 4. Bundles

```json
{
  "protocol": "trust/1",
  "origin": "https://trust.example.org",
  "entries": [ … ],
  "revocations": [ … ],
  "cursor": "1717171717.4821",
  "complete": false
}
```

`complete` is `false` when the sender truncated at its `maxEntries`; the
receiver continues from `cursor`.  A sender **must** set it honestly, because a
receiver that mistakes truncation for exhaustion silently stops syncing.

### 4.1 Export

```
GET /api/certificates/export?since=<cursor>&limit=<n>
```

Public and unauthenticated: everything it returns is signed, and a signature
carries the same weight to a stranger as to a friend.

The cursor is opaque to the receiver and ordered by the sender's own
last-modified clock.  Entries are returned in cursor order so that resuming is
well defined.

### 4.2 Import

```
POST /api/import
```

Applies §3.4 to every entry and §6 to every revocation, stores what survives,
and answers with a count of each outcome:

```json
{ "accepted": 12, "rejected": 1, "revocations": 2, "reasons": ["signature did not verify"] }
```

Rejections are reported rather than swallowed.  A node that silently drops
entries is indistinguishable from one that is broken.

Import is authenticated when it would let a stranger fill a node's disk; a node
in local mode, where the only user is the person running it, does not
authenticate.

### 4.3 Cursor

A cursor is a decimal `<epoch-milliseconds>.<row-id>` string, ordered by when
the sender last changed the row.  The row id breaks ties so that entries written
in the same tick are never skipped by a resume — a plain timestamp cursor loses
rows exactly when a node is busiest.

Cursors are opaque: a receiver stores the string and sends it back, and must not
read anything into its parts.

### 4.4 Hints

`hints` carries what the origin knows but a receiver cannot check: the account
name the key was published under, whether that account published the key
itself, and where the entry was seen.  A receiver **may** store hints for
display and **must** mark them as unverified.  A receiver **must not** let a
hint affect acceptance, ordering, or trust.

## 5. Peers and discovery

### 5.1 Peer states

| state | meaning |
|---|---|
| `seed` | configured by the operator; queried |
| `active` | discovered and admitted by policy; queried |
| `candidate` | discovered, not admitted; recorded, never queried |
| `blocked` | never queried, never re-admitted by discovery |

`autodiscover` decides whether a newly discovered peer becomes `active` or
`candidate`.  It defaults to **off**.  A protocol that adds peers to a node
without its operator's say-so is one where any stranger can make a node issue
requests on their behalf, and that is a decision an operator should make
deliberately.

### 5.2 Announcing

```
POST /api/peers/announce   { "url": "https://other.example.org" }
```

The receiving node fetches `<url>/api/federation` and requires:

* the response to parse as a descriptor with a recognised `protocol`;
* `descriptor.url` to equal the announced `url` after normalisation.

The second requirement is what stops a node being used as a scanner.  Only a
host that actually runs a node and knows its own name can be announced, so an
announcement cannot direct traffic at an arbitrary third party.

### 5.3 Peer list exchange

```
GET /api/peers   →   { "peers": [ { "url": …, "name": …, "lastSeen": … } ] }
```

A node lists only peers it queries itself (`seed` and `active`).  Publishing
`candidate` or `blocked` entries would leak both an operator's judgements and a
list of addresses that node has been asked to probe.

### 5.4 Address policy

Before any request to a peer, and again for every URL learned from one:

* the scheme must be `https`, or `http` when `allowPrivate` is set (which is
  for local mode and tests, not for deployments);
* the URL must carry no credentials, no fragment, and no query;
* the hostname must resolve, and **no** resolved address may be loopback,
  private, link-local, unique-local, or carrier-grade NAT.

The last check is what keeps a federating node from being turned into a probe
against the network it sits in — the announcement in §5.2 is attacker-supplied
input, and `http://169.254.169.254/` is a valid URL.

> **Known residual risk.**  The address check resolves the hostname and then
> issues the request, which is two separate resolutions: a name that answers
> honestly for the first and privately for the second (DNS rebinding) defeats
> it.  Closing this needs the connection pinned to the address that was
> checked, which the platform HTTP client does not currently expose.  Redirects
> are refused outright rather than followed, which removes the easier version
> of the same trick.

## 6. Revocation

A `revoked_at` column is a fact about one database.  Crossing a trust boundary
requires the withdrawal to be as checkable as the assertion was, so it is
signed by the same key.

### 6.1 Canonical bytes

```
{"fingerprint":"…","hash":"…","hasher":"…","reason":"…","revoked":"…"}
```

Same ordering rule and same escaping as §3.2.  `revoked` is RFC 3339 UTC;
`reason` may be empty but is always present, so that the bytes are determined
by the object.

### 6.2 Rules

1. The signature must verify against the key whose fingerprint is
   `fingerprint`, under the rules of §3.4.
2. A revocation suppresses exactly those certificates with the same
   `(fingerprint, hash, hasher)` whose `asserted` is **not later** than
   `revoked`.
3. A later certificate therefore reinstates: re-issuing after withdrawing is
   ordinary and needs no separate message.
4. Revocations propagate in bundles alongside entries and are never dropped for
   referring to a certificate the receiver has not seen — the certificate may
   arrive by another path afterwards.

Rule 4 means a node stores revocations it has no use for yet.  They are small,
and the alternative is a race in which withdrawal loses to assertion depending
on which arrives first.

## 7. Delegated query

```
GET /api/certificates?hash=…&hasher=…&fingerprint=…&depth=…&via=…
```

Answers from local storage, the remote cache, and — if `depth` allows — peers
asked the same question.

### 7.1 Depth and loops

`depth` is how many further hops the request may travel.  `0` is local only.  A
node clamps the received value to its own `maxDepth` and relays `depth - 1`.

TTL alone does not prevent a cycle from multiplying a request, so every relayed
request also carries `via`: the comma-separated URLs already in the chain.  A
node **must not** relay to a URL present in `via`, and **must** append its own
before relaying.  A node that finds itself in `via` answers locally without
relaying.

### 7.2 Budget

Delegation is answered under a wall-clock budget, not a peer count: one
unreachable peer must not decide how long a reader waits.  Each peer gets
`peerTimeoutMs`, the whole fan-out gets `queryBudgetMs`, peers are asked
concurrently, and whatever has arrived when the budget expires is what is
returned.  A truncated answer is marked, never presented as complete.

### 7.3 Caching

Accepted remote entries are cached with the peer they arrived from and the time
they arrived.  A cache hit within `remoteTtlS` answers without a fan-out.

The cache is a performance decision and never a trust decision: entries are
verified before they enter it, and are returned with the key and the canonical
bytes so the reader can check them again.

### 7.4 Response

```json
{
  "certificates": [ { "claim": …, "canonical": …, "signature": …, "key": …,
                      "fingerprint": …, "assurance": "signed",
                      "provenance": { "local": false, "origin": "https://…",
                                      "verifiedHere": true, "fetchedAt": … } } ],
  "truncated": false,
  "askedPeers": 3
}
```

`canonical` is included for every entry, local or remote, so that the reader
never has to reconstruct what was signed in order to check it.  `verifiedHere`
records that this node applied §3.4 — it is this node's word, and the reader is
expected to repeat the check rather than take it.

## 8. Limits

A conforming node enforces at least these, with the defaults this
implementation uses:

| limit | default | why |
|---|---|---|
| `maxDepth` | 2 | fan-out is exponential in depth |
| `maxEntries` per bundle | 500 | bounds a single response |
| `maxResponseBytes` | 2 MiB | a peer's response is untrusted input |
| `peerTimeoutMs` | 4000 | one slow peer must not own the request |
| `queryBudgetMs` | 8000 | bounds the whole fan-out |
| `remoteTtlS` | 300 | how stale a cached remote answer may be |
| `maxViaLength` | 8 | bounds the relay chain |

Every one of these is a defence against a peer that is hostile or merely
broken, and the two are not distinguishable from the outside.

## 9. Local mode

A local trust database is the same software with a different store and no
public surface: SQLite instead of Postgres, no OAuth, one identity, and
federation reduced to what a single person needs — importing bundles and
pulling from nodes they choose.

That it is the same code is the point.  "Your own database" and "a public
database" differ in deployment, not in kind, and a local database that spoke a
dialect of this protocol would be a second implementation to keep honest.
