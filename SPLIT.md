# Rewriting trust in Lean, and splitting it into four repositories

Today one repository holds a Lean library, a Lean command line tool, a
TypeScript certificate server that federates, and a React frontend.  The plan is
to separate them into four repositories and, in the same move, to write
everything except the frontend in Lean.

That second half is the larger change.  It replaces 3 470 lines of TypeScript
and its dependency tree — Express, `pg`, `openpgp.js` — with Lean, and it takes
the project from three implementations of the certificate format to two.  The
one that remains is the browser's, which is the one that should be independent:
it is where a reader checks a signature they were handed.

| repository | what it is | language |
|---|---|---|
| `chrisflav/trust` | the core: exporter, index format, certificate format, federation rules, PGP verification | Lean |
| `chrisflav/trust-server` | a certificate node: storage, sessions, federation | Lean |
| `chrisflav/trust-cli` | issue, sign, view, publish, fetch and import certificates | Lean |
| `chrisflav/trust-web` | the frontend | TypeScript |

`chrisflav/trust-action` already exists and does not move; it drives the
exporter, which stays in core.

Two parts of this are genuinely hard, and §3 says what to do about them: there
is no OpenPGP implementation in Lean, and the HTTP server this would run on
shipped in the standard library months ago.  Everything else the toolchain
already has.

## 1. What Lean can do today

Checked against the toolchain this repository pins, `leanprover/lean4:v4.32.0`,
rather than from memory.  `Std` has grown most of a server runtime:

| need | today | in Lean | status |
|---|---|---|---|
| HTTP/1.1 server | Express | `Std.Http.Server` | **in the toolchain** — async, connection limits, graceful shutdown |
| request/response types | Express | `Std.Http.Data` | URI, headers, methods, status, streaming bodies |
| async runtime | node | `Std.Async` | TCP, UDP, DNS, timers, signals, `Select` |
| concurrency | node | `Std.Sync` | `Mutex`, `Channel`, `Semaphore`, `CancellationToken` |
| parsing | hand-rolled | `Std.Internal.Parsec` | over `String` and `ByteArray` |
| time, RFC 3339 | `Date` | `Std.Time`, `Formats.iso8601` | **replaces shelling out to `date`** |
| randomness | `node:crypto` | `IO.getRandomBytes` | in the toolchain |
| JSON | `JSON` | `Lean.Json` | already used |
| CLI arguments | hand-rolled | `leanprover/lean4-cli` | maintained, tracks Lean stable |
| tests | vitest | `argumentcomputer/LSpec` + `lake test` | maintained |
| SQLite | `node:sqlite` | `leanprover/leansqlite` | official; API "likely to change"; **a tag per Lean release**, `v4.32.0` among them |
| Postgres | `pg` | — | no driver found. **Drop Postgres** |
| HTTPS client | `fetch` | — | `curl` subprocess, as the CLI does today |
| TLS | `node:tls` | — | inbound is terminated by the proxy already |
| OpenPGP | `openpgp.js` | — | `gpg` subprocess behind a `Verifier`; see §3 |
| SHA-2, HMAC | `node:crypto` | — | designed out; see §5.2 |
| base64 | `Buffer` | — | ~50 lines, needed for armor |
| gzip | nginx | — | stays with nginx; see §5.3 |

Two findings change the shape of the plan.

`Std.Http.Server.Config` carries the limits surface this protocol needs —
`maxBodySize`, `maxHeaders`, `maxHeaderBytes`, `headerTimeout`,
`keepAliveTimeout`, `maxConnections` — so most of `FEDERATION.md` §8 becomes
configuration rather than hand-written checks.

`leansqlite` releases a tag per Lean version, and `v4.32.0` is one of them — the
same convention this repository uses, and for the same reason.  So the store
needs no toolchain bump: it needs a C compiler at build time, for the SQLite
amalgamation, which CI and the container image both have.

(An earlier draft of this plan read only `main`'s `lean-toolchain`, saw
v4.34.0-rc1, and concluded a bump was unavoidable.  It is worth saying where
that went, because the store was designed around it for a while: see the
appendix.)

## 2. What the rewrite buys

Not a rewrite for its own sake.  Seven things get better, and four of them are
things the TypeScript arrangement could not have.

1. **`verify-bundle` becomes the check it claims to be.**  `README.md` says it
   "repeats, locally, precisely the check the server claims to have done".  Today
   that is approximately true: the server applies all five acceptance rules of
   §3.4, and Lean's `verifyBundle` applies them approximately — it checks the
   fingerprint an entry claims against a listing that includes *subkey*
   fingerprints, so an entry naming a subkey passes a check §3.4 rule 3 means to
   fail.  In Lean, the CLI and the server call the same function, and the
   sentence becomes literally true.
2. **One canonicalization, one acceptance implementation.**  Core, CLI and
   server share `Trust.Cert` and `Trust.Federation`; the browser is the second
   implementation, bound to the first by conformance vectors.  Two
   implementations, deliberately chosen, instead of three that drifted.
3. **The DNS-rebinding gap closes.**  §5.4 records a residual risk: the address
   is checked by one resolution and the request is made by another, and "the
   platform HTTP client does not currently expose" pinning.  `curl` does —
   `--resolve host:port:addr` sends the request to the address that was checked.
   Going out through `curl` turns a documented weakness into a fixed one.
4. **Marks from the browser can record hashes.**  Today editing a mark in the
   dev UI writes `trust-marks.json` through a Vite middleware, and a declaration
   protected from the browser reads as `protected, no snapshot` until someone
   runs `trust protect`, because recording a hash needs Lean.  A Lean dev server
   holds the environment, so it records the hash on the spot.
5. **One store instead of two dialects.**  `store/db.ts` exists to keep Postgres
   and SQLite agreeing — no `now()`, timestamps passed in from JavaScript.  With
   SQLite alone that abstraction, and the Postgres container, and `DATABASE_URL`,
   all go.
6. **The dependency tree collapses.**  Express, `pg`, `openpgp.js` and their
   transitive closure become: `lean4-cli`, `leansqlite`, `LSpec`, and `gpg` and
   `curl` as subprocesses — with `aftk` and `semantic_hash` as before.
7. **The verifier becomes formalizable.**  Nothing is proved by writing it in
   Lean, and this plan claims no theorems.  But a project whose subject is what a
   statement rests on should be able to say what its own signature check rests
   on, and a verifier in Lean is a thing that argument can eventually be made
   about.  §11 keeps that door open without walking through it.

## 3. The two hard parts

### 3.1 There is no OpenPGP in Lean

Nothing in the ecosystem verifies an OpenPGP signature.  The nearest thing,
`gdncc/Cryptography`, is the SHA-3 family in pure Lean — the wrong hash family
for OpenPGP, which wants SHA-256 and SHA-512, and SHA-1 for v4 fingerprints.
(`leancrypto` is a C library whose name is a coincidence.)

So the verification interface is fixed first and the backend is chosen second —
exactly the shape `Trust.Hash` already uses for hashers, where every snapshot
records which hasher produced it and hashes from different hashers are reported
as incomparable rather than silently diffed:

```lean
structure Verifier where
  name : String
  /-- Check `signature` over `bytes` against the armoured public `key`.
      Reports which (sub)key signed, so §3.4 rule 5 can be applied. -/
  verify : (bytes signature key : ByteArray) → IO Verdict
```

Three backends are possible behind it:

* **`gpg` as a subprocess** — what the CLI does today, and what the server should
  start with.  Correctness comes from the reference implementation; the work is
  a throwaway home directory per check and parsing `--status-fd` for `VALIDSIG`,
  which is the only way to learn *which* key signed and therefore the only way to
  apply rule 5.  Costs a process per verification (tens of milliseconds), which
  this workload can afford: entries are verified on publish, on import and on
  arrival from a peer — never on a cache hit.
* **FFI to a C library** — one process, a real crypto dependency, a C build in
  Lake.  Worth it only if the subprocess turns out to be the bottleneck.
* **`Trust.Pgp` in Lean** — armor and CRC-24, packet parsing, MPIs, RSA (modular
  exponentiation on `Nat`, which is GMP-backed and easy), Ed25519 and ECDSA,
  SHA-1/256/512, fingerprints, subkey binding signatures.  Call it 3 000 to 4 000
  lines and a test corpus generated across key types.  Verification handles no
  secrets, so the timing discipline that makes crypto dangerous to write does not
  apply — but parsing hostile input does, and this is a security boundary.

**Recommendation: ship on `gpg`, keep `Trust.Pgp` as a separate project** (§11,
Phase 6) that swaps in behind the record without the server or the CLI noticing.

### 3.2 The server stack is young

`Std.Http` is new, `leansqlite` says its API is likely to change, and neither has
the mileage of Express or `pg`.  This node accepts POSTs from strangers.

Three things make that acceptable rather than reckless.  Lean is memory-safe, so
the class of bug that makes a young C parser frightening is absent.  The protocol
was designed on the premise that a node is not trusted — §1 of `FEDERATION.md`
— so the blast radius of a server bug is bounded by what a *hostile* node could
already do: withhold entries, or fabricate `attested` ones, which do not
federate.  It cannot forge a signature, and no reader is asked to take its word:
every entry travels with the key and the canonical bytes.

The third is a matter of sequencing, and it is Phase 2: the Lean node is built
beside the TypeScript one and does not replace it until it has federated with
it.

## 4. Where every file goes

| now | then |
|---|---|
| `Trust/{Graph,Deps,Reverse,Export,Code,Marks,Hash}.lean` | **core**, unchanged |
| `Trust/Cert.lean` | **core** — keeps the claim, revocation, entry and bundle types and `canonical`; `signBytes`/`verifyBytes` move behind `Trust.Pgp`, `postJson`/`httpGet` behind `Trust.Net`, `verifyBundle` onto `Trust.Federation` |
| `Trust/Cli.lean`, `Main.lean` | **core** — re-expressed in `lean4-cli`; keeps `deps`, `rdeps`, `decl`, `export`, `sync-marks`, `marks`, `trusted`, `protect`, `characterize`, `check`, `hash-invariants`; gains `serve-marks`; loses `cert` |
| `Trust/{Pgp,Federation,Net,Store?}.lean` *(new)* | **core** — §5.1 |
| `conformance/` *(new)* | **core** |
| `DESIGN.md`, `FEDERATION.md` | **core** |
| `server/src/certificate.ts` (229) | **core** `Trust/Cert.lean` + `Trust/Pgp.lean` |
| `server/src/federation/protocol.ts` | **core** `Trust/Federation.lean` (§3.4, §6) |
| `server/src/federation/address.ts` | **core** `Trust/Net.lean` (§5.4, with pinning) |
| `server/src/{config,auth,routes,index}.ts`, `store/`, `federation/{client,service}.ts` | **trust-server**, in Lean |
| `server/src/testing/keys.ts` | **trust-server** test support, or core if the CLI's tests want it |
| `server/**/*.test.ts` (1 101 lines) | **trust-server**, as LSpec |
| `docker/Dockerfile`, `.env.example`, the `db`/`server`/`peer` services | **trust-server** — `db` deleted, the image becomes a Lean build |
| `web/src/**`, `index.html`, `vite.config.ts` | **trust-web**, unchanged TypeScript |
| `web/marksApi.ts` (119) | **deleted** — the dev proxy forwards to `trust serve-marks` |
| `docker/Dockerfile.web`, `docker/nginx.conf` | **trust-web** |
| `deploy/trust.merten.dev.conf` | **trust-web** — **referenced by `README.md` and not in the repository**; recover it from the host it deploys |
| `.github/workflows/{lean_action_ci,trust-index}.yml` | **core** |
| `LICENSE`, the LLM-generated warning | copied into all four |

The frontend keeps its own `canonicalClaim`, its index reader and its client, as
it has them today.  **The npm package the previous version of this plan proposed
is not needed**: with the server and the CLI in Lean there is no second
TypeScript consumer to share with, and what binds the browser to Lean is
`conformance/`, not a package.

## 5. The pieces

### 5.1 Core grows four modules

* **`Trust.Pgp`** — the `Verifier` record of §3.1, a `gpg` backend, signing
  (unchanged: bytes to `gpg` on stdin, no key material in this process), key
  parsing far enough to report a fingerprint, and armor/base64.
* **`Trust.Federation`** — §3.4 acceptance, §6 revocation semantics, bundle and
  descriptor parsing and serialisation, cursor handling.  One implementation for
  the server's import path and the CLI's `verify-bundle`.
* **`Trust.Net`** — an HTTP client over `curl`: bodies on stdin, no shell
  quoting, `--max-filesize` for §8's 2 MiB, `--no-location` because §5.4 refuses
  redirects rather than following them, and `--resolve` to pin the address that
  the policy check approved.  The address policy itself — scheme, no credentials,
  no fragment, no query, and no loopback/private/link-local/ULA/CGNAT resolution
  — comes with it.
* **`Trust.Time`** — `Std.Time` in place of spawning `date -u`.

### 5.2 The server

`Std.Http.Server` with a handler per route; `Std.Sync.Mutex` around the store;
`leansqlite` with WAL, prepared statements and the `<epoch-ms>.<row-id>` cursor
of §4.3.  Federation runs on `Std.Async` — peers asked concurrently under
`queryBudgetMs`, which is `Std.Async.Select` over timers rather than
`Promise.race`.

**Sessions stop needing crypto.**  `auth.ts` signs a stateless cookie with
HMAC-SHA256; with a database in hand, a session is an opaque 32-byte value from
`IO.getRandomBytes` stored in a row, compared in constant time.  That is fewer
moving parts than the thing it replaces and it removes SHA-2 from the
requirements list.  GitHub OAuth keeps its `state` parameter — also random bytes
— and its two calls out through `Trust.Net`.

### 5.3 What stays in front of it

The deployment already puts Apache in front, terminating TLS and putting the
frontend at `/` and the server at `/api/` and `/auth/` on one origin.  That does
not change, and neither does nginx serving the frontend bundle and the exported
indexes: `decls.jsonl` is tens of megabytes and gzip is most of its load time,
Lean has no deflate, and a reverse proxy is configuration rather than code.

So "everything in Lean" means everything this project *writes*.  The Lean server
owns `/api/` and `/auth/`; static bytes stay with the thing that is good at
them.

### 5.4 The CLI

`lean4-cli`, and the certificate workflow on core's modules: `issue`, `sign`,
`show`, `verify`, `publish`, `revoke`, `fetch`, `who-trusts`, `verify-bundle`,
`import`.  Because it is Lean it can hash directly — `issue` runs under `lake
env` in the target repository as `trust cert issue` does today — so the
`trust hash` hand-off the TypeScript version of this plan needed does not exist.

`show` and `who-trusts` are new: rendering a claim, its canonical bytes and its
verdict is only possible in the browser today.

## 6. Versioning

The rewrite simplifies this to almost one axis.

| axis | who reads it | changes when |
|---|---|---|
| toolchain tag `v4.32.0` | `trust-action`, and now the server and CLI repositories too | Lean moves |
| wire protocol `trust/1` | every node, every stranger's node | the format changes incompatibly — ideally never |
| index schema in `meta.json` | the frontend | the exported layout changes |

Everything built from core is now pinned to a Lean toolchain, the server and the
CLI included.  That is the real cost of writing them in Lean: a Lean bump moves
the whole system at once, and a server patch cannot ship without building Lean.
In exchange there is one convention instead of four, and it is one this project
already runs on.

`trust-server` and `trust-cli` adopt core's convention — a tag named for the
toolchain it was built on.

## 7. What binds the frontend to Lean

`conformance/` in core, language-neutral JSON, generated by the Lean
implementation and committed.  It matters more after this rewrite than before,
because it is now the *only* thing keeping the browser and Lean in step:

* `claims.json` — claims and their canonical bytes, including `"quotes"`,
  backslashes, non-ASCII, C0 controls, and a note that tries to forge a field
  (`","hash":"0000…`).  `GOLDEN_CLAIM`, promoted out of a frontend test file.
* `revocations.json` — §6.1.
* `entries.json` — entries that must be accepted, and one for each way §3.4 says
  to reject: a private key block, a mismatched fingerprint, **a signature by a
  subkey outside the bundle**, a bad `hash` shape, an unparseable `asserted`.
* `bundle.json`, `descriptor.json` — §4 and §2, complete and truncated.
* `index-tiny/` — a real exported index, which is what
  `web/src/data/index.test.ts` skips today when nobody has run an export.

Core checks them with LSpec; `trust-web` checks them with vitest.

## 8. Phases

### Phase 0 — three spikes, before anything is committed to

Throwaway code in core, on a branch.  The deliverable of each is a measured
answer.

1. **`Std.Http`**: a node answering `GET /api/health` and a JSON `POST`, with
   `Server.Config` limits set from §8, under a few thousand requests.  Establishes
   the handler shape and whether the limits surface really covers the protocol's.
2. **`leansqlite`**: the certificates, revocations and peers schema; prepared
   statements; WAL; and the §4.3 cursor query.  Also settles the toolchain bump
   to ≥ 4.34.
3. **`Trust.Pgp` on `gpg`**: all five §3.4 rules including subkey binding via
   `--status-fd`, against a corpus of RSA, Ed25519 and subkeyed keys, with the
   per-verification cost measured.

*Done when:* each spike answers its question, or a phase is rewritten around the
answer it gave.

### Phase 1 — core grows the shared halves

`Trust.Pgp`, `Trust.Federation`, `Trust.Net`, `Trust.Time`; `conformance/`
generated and committed; `lean4-cli` adopted; LSpec and `lake test` in place;
`verifyBundle` re-expressed on `Trust.Federation` so the CLI applies all five
rules.  The TypeScript server and frontend are untouched and keep working.

*Done when:* the Lean and TypeScript implementations both pass `conformance/`,
and `trust cert verify-bundle --from https://trust.merten.dev` agrees with the
server on every entry it holds — including ones the old three-rule check
accepted.

### Phase 2 — `trust-server`, in Lean, beside the old one

A new repository, written against core.  The TypeScript server stays running and
its test suite stays green throughout.  The federation suite is ported to LSpec —
three nodes on loopback, which is easier in Lean than in Node because all three
can be `Async` tasks in one process, though at least one test should keep them as
separate processes.

The cutover test is the point of the phase: **a Lean node and the TypeScript node
federate with each other.**  A certificate published to one is found through the
other, a tampered entry is refused, a question travels two hops, a signed
withdrawal propagates.  `FEDERATION.md` opens by saying the protocol is written
down because the other end is not this code; the TypeScript server's last job is
to be that other end.

*Done when:* the two implementations federate in both directions, the Lean node
passes the ported suite, and the deployed node runs it.

### Phase 3 — `trust-cli`

A new repository on core's modules.  Then delete the `cert` subcommands from
core's binary, leaving a stub that names the replacement until the next
toolchain bump.

*Done when:* every `trust cert …` invocation in `README.md` has an equivalent
that produces a byte-identical signed certificate, and the certificate it issues
verifies against `gpg --verify` and against the server.

### Phase 4 — `trust-web`

`git filter-repo --path web/ --path docker/Dockerfile.web --path
docker/nginx.conf`, so blame survives.  Delete `marksApi.ts`; point the Vite dev
proxy at `trust serve-marks`, which can record a real hash where the middleware
could not.  Add `deploy/`.

*Done when:* the frontend builds, reads `conformance/index-tiny/`, talks to a
Lean node, and protecting a declaration from the browser produces a snapshot
rather than `protected, no snapshot`.

### Phase 5 — retire the TypeScript server

Archive the old implementation with a README that says what replaced it.  Core's
README is rewritten around the exporter, the index layout, the protocol and four
links; `docker/` leaves core; `.gitignore` loses `/server/dist` and `/web/dist`.

Nightly, core runs the four together: build the exporter → export `index-tiny` →
start a node → `trust-cert issue` → `sign` → `publish` → `fetch` →
`verify-bundle` → build the frontend against the same index.

### Phase 6 — `Trust.Pgp`, natively (optional, separate)

Swap the `gpg` subprocess for a Lean implementation behind the `Verifier` record.
Its acceptance test already exists: `conformance/entries.json`, plus the corpus
from Phase 0's third spike, plus differential testing against `gpg` on every
entry the deployed node holds.  Only worth starting when the rest is boring.

## 9. Decisions

**1. `gpg` subprocess, or write the verifier?**  Assumed: subprocess first,
interface fixed so the answer can change later.  Writing it is the more
interesting project and the one that removes the last non-Lean dependency from
the verification path; it is also a security boundary, and doing it under time
pressure while three repositories wait on it is the wrong order.

**2. Keep the CLI as its own repository?**  Assumed: yes, because it was asked
for — but the honest note is that the Lean rewrite weakens the reason.  In the
TypeScript plan the CLI split at the point where the Lean environment stopped
being needed; now both sides are Lean, both are toolchain-pinned, and the split
is about what the tool is *for* — a person's keys and network, versus a library's
CI — rather than about what it can do.  Folding it back into core's binary is a
defensible alternative that costs nothing technically.

**3. Drop Postgres?**  Assumed: yes, since no Lean driver exists and SQLite in
WAL suits the workload — a node's writes are rare and its reads are cached.  The
alternatives are writing the Postgres wire protocol on `Std.Async.TCP` (a real
but bounded project, and a second store to keep honest) or keeping a small
TypeScript writer next to the Lean node, which gives up the point of the
exercise.

## 10. Risks

* **Everything moves on a Lean bump, including the deployed node.**  Accept it;
  the alternative was four version axes.  Keep the toolchain bump its own commit
  in each repository, as `fc94653` was.
* **`leansqlite`'s API "is likely to change"**, and `Std.Http` is young.  Both
  are exercised by Phase 0 before anything depends on them, and both sit behind
  a module of ours rather than being called from every route.
* **The `gpg` subprocess is a per-request process.**  Measured in Phase 0.  If
  it is too slow the answer is FFI, not shipping something unverified.
* **Rule 5 was not being applied by the CLI.**  It is fixed in Phase 1 — before
  any of the moving — because it is a correctness bug in what is shipping today,
  not a refactoring detail.
* **Two implementations, not three.**  Deliberate, but it means the browser's
  code is now the only cross-check on the canonical bytes.  `conformance/` is
  what makes that safe, so it is committed in Phase 1 rather than assembled
  later.
* **Split histories are imperfect.**  `server/` and `web/` share commits
  (`0a5a0e6`, `8912b47`); `trust-web` will carry trimmed versions of them.  The
  server is not filtered at all — it is rewritten, so its new repository starts
  clean, and the TypeScript history stays reachable in core.
* **A smaller contributor pool.**  Fewer people write Lean than TypeScript.  The
  offset is that there is much less code and far fewer dependencies to review,
  which is the same argument this project makes about trusting anything else.

## 11. Chores

- [ ] `LICENSE` and the experimental/LLM-generated warning into all four
- [ ] Repository descriptions and a link back to core from each
- [ ] `trust-action`'s README links to core, and stays correct
- [ ] The server image becomes a Lean build — multi-stage, with `gpg` and `curl`
      in the runtime layer, still unprivileged
- [ ] `docker/.env.example` follows the server; `DATABASE_URL` and the Postgres
      password leave it
- [ ] `deploy/trust.merten.dev.conf` recovered from the host and committed to
      `trust-web`, since `README.md` documents a file that is not here

## Sources

Ecosystem claims above were checked rather than recalled.

* Lean toolchain contents: `~/.elan/toolchains/leanprover--lean4---v4.32.0`
* [leanprover/leansqlite](https://github.com/leanprover/leansqlite) — official
  SQLite bindings; higher-level API "more experimental… likely to change"
* [leanprover/leansqlite tags](https://github.com/leanprover/leansqlite/tags) — a
  tag per Lean release; `v4.32.0` is the one this toolchain takes.  `main` is on
  v4.34.0-rc1, which is what an earlier draft of this plan read instead
* [leanprover/lean4-cli](https://github.com/leanprover/lean4-cli) — CLI parsing
* [argumentcomputer/LSpec](https://github.com/argumentcomputer/LSpec) — testing
* [algebraic-dev/http](https://github.com/algebraic-dev/http) — the HTTP work
  that became `Std.Http`
* [gdncc/Cryptography](https://github.com/gdncc/Cryptography) — SHA-3 family in
  pure Lean; no SHA-2, no OpenPGP
* [Reservoir](https://reservoir.lean-lang.org/) — no Postgres driver, no TLS
  package found

## Appendix: what the implementation changed about this plan

Written after the fact.  A plan that is not corrected by contact with the thing
it planned is a plan nobody followed.

**Phase 0 answered its three questions, and one of them differently.**
`Std.Http` serves real requests over a real socket — a handler is about ten
lines, and `Std.Http.Server.Config` covers most of §8 as configuration.  `gpg
--status-fd` reports `VALIDSIG <signing-key> … <primary-key>`, so rules 3 and 5
are both checkable, and the per-verification cost is a process spawn the
workload can afford.  The store spike went the other way.

**The store was an append-only log for a while, on a premise that was false.**
I read only `main`'s `lean-toolchain`, saw v4.34.0-rc1, and concluded that
`leansqlite` would force a toolchain bump on core — and therefore on the pinned
`semantic_hash` revision that every certificate hash depends on.  That would
have been a real reason.  But `leansqlite` tags a release per Lean version, the
same convention this repository uses, and `v4.32.0` is one of them.  Checking
the default branch of a dependency and not its tags is a cheap mistake to make
and an expensive one to build on: the log was about 850 lines, and every one of
them existed because of it.

The store is SQLite.  What is true of the log and worth keeping in mind: it
needed no C compiler, and v4.32.0 exposes no `fsync`, so its durability went
through a `sync --data` subprocess.  SQLite needs a C toolchain at build time —
which CI and the image both have — and does its own durability, so that hack is
gone with it.

**The npm package was never needed.**  With the server and the CLI in Lean there
is no second TypeScript consumer, so `conformance/` is the whole contract, and
the frontend's CI fetches it rather than depending on a package.  Decision 3
above dissolved rather than being decided.

**Dependency revisions are not on `main`.**  `lean4-cli` builds from its
`v4.32.0` tag; `main` is on v4.34.0-rc1.  `LSpec` builds at `3e23a4ad`, the last
revision before its Plausible integration, which does not compile here.  Both
are pinned with a comment saying why, because a future reader will otherwise
"helpfully" move them to `main`.

**The bug in §3.4 was rule 3, not rule 5.**  The old check imported the entry's
key into an empty keyring and then looked for the claimed fingerprint anywhere
in `gpg --with-colons --fingerprint`, which lists subkeys too.  Isolation was
already enforcing rule 5 as a side effect; what leaked through was an entry
naming a *subkey's* fingerprint, which rule 3 requires to be the primary's.  It
is fixed, it has a test, and it is a vector in `conformance/entries.json` so
that the next implementation cannot repeat it.

**Timestamps had to become more liberal, not less.**  Reviewing the node's store
turned up a second RFC 3339 parser, written because core's could not read a
fractional second.  §3.4 rule 1 asks only that `asserted` parse, so the fix
belonged in core: fractions are accepted and kept to milliseconds, and the
comparisons order by them.  What is *written* is unchanged — seconds, and a
literal `Z`.
