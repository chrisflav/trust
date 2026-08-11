# trust

Estimating the trust debt of a Lean statement: what it definitionally rests on,
and what rests on it.  See [DESIGN.md](DESIGN.md) for the goals.

> [!WARNING]
> **Experimental, LLM-generated, and not reviewed by a human.**
>
> This code was written by an LLM (Claude).  No human has read it line by line,
> and the performance and correctness claims in this README were measured by the
> same process that wrote the code — they have not been independently checked.
>
> The point of this tool is to help you decide what to trust.  Do not extend that
> trust to the tool: read the code before relying on any of it, and treat what it
> reports as a question worth checking rather than an answer.

Dependency analysis builds on [aftk](https://github.com/mathlib-initiative/aftk);
what trust adds is the *definitional* view — edges rather than a flat set,
dependencies of the **statement** rather than of statement-and-proof together,
and a data-carrying/proof distinction so that traversal stops at proofs.

## Building

```bash
lake build
```

## Querying a declaration

`trust` reads a repository's `.olean` files, so run it inside the target
repository via `lake env`:

```bash
cd /path/to/mathlib4
lake env /path/to/trust/.lake/build/bin/trust deps Mathlib.Data.Nat.Defs Nat.gcd
lake env /path/to/trust/.lake/build/bin/trust rdeps Mathlib.Data.Nat.Defs Nat.gcd --module 'Mathlib.Algebra.*'
```

Both print a JSON graph on stdout.  `--module` patterns are aftk's, so they
behave identically to `lake exe aftk`.

`trust decl` renders a declaration instead, as text plus the character ranges
that refer to constants:

```bash
./.lake/build/bin/trust decl Init.Data.Nat.Gcd Nat.gcd
```

The ranges come from the delaborator's info map, so they survive notation and
instances — `m.gcd n = n.gcd m` correctly reports `Nat.gcd` and `Eq`.  Offsets
are UTF-16 code units, so they can be used as JavaScript string indices
directly.  Proof bodies are never rendered; definition bodies are.

For declarations in Lean core no `lake env` is needed:

```bash
./.lake/build/bin/trust deps Init.Data.Nat.Gcd Nat.gcd
```

## Marks: trusted, characterized, protected

Everything above is *derived* — re-running the exporter reproduces it exactly.
Marks are the opposite: they are what a person decided, so they live in a file
of their own, `trust-marks.json`, and each records the commit it was made at.
A judgement about a declaration only means something against a version of that
declaration.

The file is plain JSON and diffs cleanly, so a project that wants shared
judgements can commit it; it is git-ignored here, because whose judgements
those should be is the project's decision rather than the tool's.  Use
`--marks <path>` to keep several.

```bash
trust trusted      Init.Data.Nat.Gcd Nat.gcd --note "reviewed by hand"
trust protect      Init.Data.Nat.Gcd Nat.gcd
trust characterize Init.Data.Nat.Gcd Nat.gcd Nat.gcd_dvd_left Nat.gcd_dvd_right Nat.dvd_gcd
trust check        Init.Data.Nat.Gcd
trust marks
```

`protect` records a hash of the declaration's content; `check` compares each
protected declaration against its most recent snapshot and **exits non-zero**
when one has changed, so it can gate CI:

```
CHANGED  Nat.gcd: 4e36146e78af9850 at 5f6b07a → 91c0a2ff31bd7e04 now
MISSING  Nat.foo: protected but not present in this environment
```

Hashing goes through a `Hasher` (`Trust/Hash.lean`).  The default is
[semantic_hash](https://github.com/mathlib-initiative/semantic_hash), which is
stable under changes that do not change meaning; the alternative the record
exists for is a structural hash, which never misses a real change but does
report renamed binders as changes.  Every snapshot records which hasher
produced it, and hashes from different hashers are reported as incomparable
rather than silently diffed.

`trust export` carries the marks into the index as `marks.json`, resolving each
protected declaration's status on the way — deciding whether content still
matches a snapshot needs the environment, so the browser is handed the verdict.

Marks change far more often than the library does, and re-exporting Mathlib to
record one judgement is twenty-five minutes, so they can be refreshed on their
own:

```bash
cd /path/to/mathlib4
lake env /path/to/trust/.lake/build/bin/trust sync-marks \
  --repo mathlib --out /path/to/trust/web/public/index \
  --marks /path/to/trust/trust-marks.json Mathlib
```

That takes about ten seconds.  Note the explicit `--marks`: the export runs
inside the *target* repository, so the default of `trust-marks.json` in the
working directory is that repository's, not `trust`'s.

## The frontend

The web UI reads a precomputed static index.  Generate one, then serve it:

```bash
./.lake/build/bin/trust export --repo core --out web/public/index --with-bodies --with-code Init
cd web && npm install && npm run dev
```

`--with-bodies` also exports the edges that come from definition bodies.  Without
it, definitions do not unfold in the UI.

Proof terms are *not* exported, in either direction.  A proof is a leaf: what a
proof term happens to mention is not something the theorem rests on — only its
statement is — so a theorem shows the dependencies of its statement and nothing
else, and never turns up as a dependent of a declaration its proof merely
touched.  For Lean core that rule is 89% of the body edges.

`--with-code` exports the rendered declarations that the UI displays and makes
clickable.  It is sharded under `code/` and fetched on demand, since it is the
largest part of an index.  For Lean core the whole export takes about 30 seconds
and produces roughly 40 MB, of which 25 MB is code.

Marks are shown next to the declaration they are about, and can be edited from
the browser while `npm run dev` is running: a Vite middleware (`web/marksApi.ts`)
reads and writes `trust-marks.json`.  A deployed index is a static site with
nowhere to write, so it shows marks read-only.

Editing from the browser records *which* declarations are marked; recording a
content hash still needs Lean, so a declaration protected from the UI reads as
`protected, no snapshot` until `trust protect` is run for it.  The dev server
merges the existing snapshot history on every write, so editing from the browser
never discards hashes the browser does not know about.

## Generating an index in CI

An index is only worth as much as it is current, and a library moves whether or
not anyone remembers to re-export it.  So the export belongs in the library's
own CI, as a step —
[chrisflav/trust-action](https://github.com/chrisflav/trust-action), which
builds `trust`, runs the export inside your checkout, and hands back the
directory it wrote:

```yaml
name: Trust index

on: [push, workflow_dispatch]

jobs:
  index:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - id: trust
        uses: chrisflav/trust-action@v1
        with:
          module: MyLibrary
      - uses: actions/upload-artifact@v4
        with:
          name: trust-index
          path: ${{ steps.trust.outputs.index-root }}
```

`module` is the only input you have to give: the root module whose import
closure is indexed, exactly the argument `trust export` takes.  Everything else
has a default — the index is named after the repository, written to
`trust-index/<name>/`, and the library is built first, since the export reads
`.olean` files and something has to have produced them.  Statement edges, body
edges and rendered code are all exported; semantic hashes are not, because that
is a further whole-environment pass and only an index that will be held up
against trust certificates needs them (`with-hashes: 'true'`).

The remaining inputs, the outputs and the rest of it are documented in [that
repository's README](https://github.com/chrisflav/trust-action#inputs).  Worth
knowing here: `trust-bin` is an output, so a later step can run `trust check` to
gate the build on protected declarations without building `trust` twice.

### Which trust indexes your library

Nothing in the workflow above names a version of `trust`, and that is the point.
An exporter can only read the `.olean` files of the Lean it was built on, so a
release of `trust` is a release *for* a toolchain and its tag says which:
`v4.31.0`, `v4.32.0`.  The action reads your `lean-toolchain` and takes the tag
of that name, which means bumping Lean is one edit rather than two.  Its
`trust-ref` input is there for when you would rather say it yourself.

That is also why the action is a separate repository: it is versioned by its own
inputs and outputs, this is versioned by Lean, and holding them together made
every caller name one ref for both.

> [!WARNING]
> A `.olean` file can only be read by the exact Lean version that wrote it, so
> `trust` can only index a library on **its own toolchain** — this one is
> `leanprover/lean4:v4.32.0`.  The action compares the two `lean-toolchain`
> files and stops there, naming both versions, rather than letting it fail
> somewhere inside Lean with a message about a module header.
>
> There is deliberately no option to build `trust` on your toolchain instead:
> its source only compiles against the Lean it pins, so that would trade a clear
> error for a compile failure in someone else's code.  If the versions differ,
> either the library or `trust` has to move.

### Releasing a trust for a new Lean

Because the tag is the whole of the mapping, cutting a release is naming it
after the toolchain the release was built on:

```bash
git tag -a v4.33.0 -m "trust for Lean v4.33.0"
git push origin v4.33.0
```

The name has to match `lean-toolchain` at that commit or the action will refuse
the pair it was handed — which is what `require-matching-toolchain` is for once
`trust-ref` is chosen automatically, and the only way the convention can be
wrong.

This repository runs the action against a Lean core module on every pull
request (`.github/workflows/trust-index.yml`), pointing it at the pull request's
own exporter, so a change here is tested through the thing that will ship it.

### Pointing the interface at the result

The frontend reads `<root>/<name>/meta.json`, and `?repo=` selects the name, so
an artifact downloaded from CI is unpacked and served as it stands:

```bash
unzip trust-index.zip -d web/public/index
cd web && npm run dev      # http://localhost:5173/?repo=mylibrary
```

A deployed instance is the same thing: `docker/docker-compose.yml` bind-mounts
`web/public/index`, so replacing a directory under it publishes a new index
without rebuilding anything.

The CLI operates on a downloaded index too — `trust sync-marks` refreshes the
judgements in one in seconds, without the export that produced it:

```bash
cd /path/to/mylibrary
lake env /path/to/trust/.lake/build/bin/trust sync-marks \
  --repo mylibrary --out /path/to/trust/web/public/index \
  --marks trust-marks.json MyLibrary
```

## Trust certificates (server)

A certificate is one person's assertion about one declaration, keyed by its
**semantic hash** rather than its name.  `semantic_hash` computes that over the
definitional closure, so a declaration's hash incorporates the hashes of
everything it references: vouching for a hash vouches for the whole subtree
beneath it, and any change in meaning underneath invalidates the certificate on
its own.  It also makes certificates portable — one written against Mathlib at
one commit applies anywhere that declaration still hashes the same.

The hash is deliberately blind to anything that is not meaning.  `trust
hash-invariants` checks this rather than asserting it: renaming a declaration or
its binders, or making an argument implicit instead of explicit, leaves the hash
untouched, while genuinely different definitions still differ.

Bring the server up:

```bash
cd docker
cp .env.example .env      # fill in SESSION_SECRET and a GitHub OAuth app
docker compose up --build
```

Postgres is not published to the host, and the server runs unprivileged.

### Deploying

`deploy/trust.merten.dev.conf` puts Apache in front of the compose stack, with
the frontend at `/` and the server at `/api/` and `/auth/` on **one origin**.
That is worth insisting on: same-origin means no CORS at all, and a first-party
session cookie, which browsers increasingly refuse to send cross-site however
correctly it is labelled.

```bash
a2enmod proxy proxy_http ssl headers rewrite
cp deploy/trust.merten.dev.conf /etc/apache2/sites-available/
a2ensite trust.merten.dev && apachectl configtest && systemctl reload apache2
certbot --apache -d trust.merten.dev
```

In `docker/.env`:

```bash
PUBLIC_URL=https://trust.merten.dev
APP_URL=https://trust.merten.dev
COOKIE_SECURE=true
BIND_ADDR=127.0.0.1        # containers must not be reachable past the proxy
```

and set the OAuth App's callback to
`https://trust.merten.dev/auth/github/callback`.

The frontend bakes the server URL in at build time, so after changing
`PUBLIC_URL` run `docker compose up --build web`.

### What the server is, and is not

It is a place to publish and find certificates.  It is **not** a trusted party:

* **Private keys are never uploaded.**  Signing happens on the machine that
  holds the key; the server takes public keys only, and refuses anything that
  looks like a private one.
* **Signature checks are a cache, not the authority.**  Every certificate is
  returned with the canonical bytes that were signed, so a client can repeat the
  check itself.  A compromised server can withhold certificates or fabricate
  `attested` ones — it cannot forge a `signed` one.
* **Trust is not transitive.**  Trusting someone counts their certificates and
  nobody else's; it never silently enrols the people they trust.

| assurance | means |
|---|---|
| `signed` | an OpenPGP signature over the claim verified against the issuer's key |
| `attested` | a signed-in GitHub account asserted it, on this server's word alone |

A key also records whether it was found among the account's published GitHub
keys (`github`) or merely uploaded here (`self`), which is a materially
different claim about who owns it.

## Federation

There is no central trust database, and this one is not it.  A server is a
*node*: it holds the certificates published to it, learns others from the nodes
it talks to, and passes on questions it cannot answer.  The protocol is
[FEDERATION.md](FEDERATION.md); what follows is how to use it.

The organising rule is that a node relays other people's assertions and is never
a party to them.  So:

* **Only signed certificates federate.**  `attested` means "a signed-in account
  said so, and this server vouches for that", which is not something a third
  party can check or repeat — so it stays where it was made.
* **Identity across a boundary is a key fingerprint**, not a login.  A node can
  verify that a key signed something; it cannot verify who owns the key.  Names
  travel as unverified hints and are shown as such.
* **Every federated entry is checked before it is stored**, and is handed back
  with the public key and the exact bytes that were signed, so you can check it
  again yourself — in the browser, or with `trust cert verify-bundle`.

### Your own database

A local trust database is the same server with a different store and no public
surface: SQLite instead of Postgres, no OAuth, one identity.

```bash
cd server && npm install && npm run build && npm run local
```

It listens on `:8090` and keeps its data in `~/.local/share/trust/trust.db`
(`SQLITE_PATH` to move it).  Point the CLI at it and publish as normal:

```bash
export TRUST_SERVER=http://127.0.0.1:8090
trust cert issue Init.Data.Nat.Gcd Nat.gcd -o gcd.json
trust cert sign gcd.json
trust cert publish gcd.json
```

That it is the same code as a public node is the point.  "Your own database" and
"a public database" differ in deployment, not in kind.

### Importing from another database

Nothing about pulling somebody's certificates requires their permission or
yours: a node's export is public, because everything in it is signed.

```bash
# Look at what a node has, checking every signature here before believing any
# of it — in a throwaway gpg keyring, so your own is untouched.
trust cert verify-bundle --from https://trust.merten.dev

# The same check, then hand what survives to your own database.
trust cert import --from https://trust.merten.dev --server http://127.0.0.1:8090
```

`verify-bundle` is the command that makes a server unnecessary rather than
trusted: it repeats, locally, precisely the check the server claims to have
done.

### Talking to other nodes

A node reads its starting peers from `FEDERATION_SEEDS`.  Everything else is the
operator's decision, through endpoints that need `ADMIN_TOKEN`:

```bash
curl -X POST $SERVER/api/peers/pull          -H "Authorization: Bearer $ADMIN_TOKEN" -d '{}'
curl -X POST $SERVER/api/peers/status/active -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H 'Content-Type: application/json' -d '{"url":"https://other.example.org"}'
```

Anyone may *announce* a node (`POST /api/peers/announce`), and a node so
announced is recorded as a `candidate` — never queried until the operator
promotes it, unless `FEDERATION_AUTODISCOVER` is on.  The announced URL is
checked against what that node says its own address is, which is what stops this
endpoint being used to make your server probe addresses on your network.

To watch two nodes federate:

```bash
cd docker && docker compose --profile federation up --build
```

### Asking a question that travels

```
GET /api/certificates?hash=<h>&hasher=<name>&depth=2
```

The node answers from its own store and its cache, and — if `depth` allows —
asks its peers the same question, one hop shallower.  Fan-out runs under a
wall-clock budget rather than a peer count, and an answer that may be short says
so: *nobody vouches for this* and *I could not find out* are different sentences.

Certificates come back labelled with where they came from, and the frontend
offers a **check it yourself** button next to each one, which verifies the
signature in the page against the key that travelled with it.

### Withdrawing a certificate

Deleting a row hides it on one server.  Once certificates travel, a withdrawal
has to be as checkable as the assertion was, so it is signed by the same key:

```bash
trust cert revoke gcd.json --note "the proof was wrong" --server $TRUST_SERVER
```

Only the key that made an assertion can withdraw it, and a *later* certificate
for the same content reinstates it — so re-issuing after a withdrawal is
ordinary and needs no second message.

### Index layout

```
meta.json         schema version, counts, revision
decls.jsonl       one JSON object per declaration, id-ordered
stmt-edges.bin    flat little-endian int32 (src, tgt) pairs
body-edges.bin    the same, for definition bodies (never for proof terms)
code/<n>.jsonl    rendered declarations, 2000 per shard
marks.json        human judgements, with protection resolved (when any exist)
```

Edges are binary rather than JSON because the browser maps them straight onto an
`Int32Array` with no parsing.  As JSON they were 28 MB of text and over a million
transient strings per load, which exhausted memory in Firefox.

To index another repository, run the export inside it:

```bash
cd /path/to/mathlib4
lake env /path/to/trust/.lake/build/bin/trust export \
  --repo mathlib --out /path/to/trust/web/public/index --with-bodies Mathlib
```

## Tests

```bash
cd web    && npm test
cd server && npm test && npm run typecheck
```

The frontend suite includes a check against a real exported index, which is
skipped when none has been generated.

The server suite starts three real nodes on loopback and federates between them:
a certificate published to one is found through another, a tampered one is
refused, a question travels two hops, a relay loop is refused, and a signed
withdrawal propagates.  It runs on SQLite, which is also what local mode uses,
so the store both backends share is exercised by every test in it.

## License

[Apache License 2.0](LICENSE).
