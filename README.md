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
  --repo mathlib --out /path/to/index \
  --marks /path/to/trust/trust-marks.json Mathlib
```

That takes about ten seconds.  Note the explicit `--marks`: the export runs
inside the *target* repository, so the default of `trust-marks.json` in the
working directory is that repository's, not `trust`'s.

Marks can also be edited from the frontend while `trust serve-marks` is running,
which is what answers `/api/marks` there:

```bash
lake env /path/to/trust/.lake/build/bin/trust serve-marks --marks trust-marks.json MyLibrary
```

Given a module it holds that module's environment, so a declaration protected
from the browser records its hash on the spot rather than reading as
`protected, no snapshot` until someone runs `trust protect`.  Snapshots are
merged on the server side: the browser says which declarations are marked and
why, and never sends the history, which it has no way to know.

## Exporting an index

The frontend reads a precomputed static index.  Generate one:

```bash
./.lake/build/bin/trust export --repo core --out index --with-bodies --with-code Init
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
edges, rendered code and semantic hashes are all exported.  The hashes are a
further pass over the whole environment, which is not free — but an index
exported without them cannot be given them afterwards, and what they answer is
whether a declaration is still the one a certificate was issued for, a question
that only arrives later (`with-hashes: 'false'` for an index that will only be
read).

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

The frontend is [chrisflav/trust-web](https://github.com/chrisflav/trust-web).
It reads `<root>/<name>/meta.json`, and `?repo=` selects the name, so an artifact
downloaded from CI is unpacked and served as it stands:

```bash
unzip trust-index.zip -d /path/to/trust-web/public/index
cd /path/to/trust-web && npm run dev    # http://localhost:5173/?repo=mylibrary
```

A deployed instance bind-mounts the same directory, so replacing a directory
under it publishes a new index without rebuilding anything.

The exporter operates on a downloaded index too — `trust sync-marks` refreshes
the judgements in one in seconds, without the export that produced it:

```bash
cd /path/to/mylibrary
lake env /path/to/trust/.lake/build/bin/trust sync-marks \
  --repo mylibrary --out /path/to/index --marks trust-marks.json MyLibrary
```

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
  --repo mathlib --out /path/to/index --with-bodies Mathlib
```

## The four repositories

This one is the core: the exporter, the index format, and the rules the rest of
the system agrees on.  Everything else that used to live here now lives beside
it, because it was versioned by something different.

| repository | what it is |
|---|---|
| **chrisflav/trust** | this one — the Lean library, the `trust` exporter, `FEDERATION.md`, and `conformance/` |
| [chrisflav/trust-cli](https://github.com/chrisflav/trust-cli) | `trust-cert`: issue, sign, view, publish, fetch and import certificates |
| [chrisflav/trust-server](https://github.com/chrisflav/trust-server) | a certificate node: storage, sessions, federation |
| [chrisflav/trust-web](https://github.com/chrisflav/trust-web) | the frontend |
| [chrisflav/trust-action](https://github.com/chrisflav/trust-action) | the GitHub action that drives the exporter |

The first three are Lean and depend on this library.  The frontend is
TypeScript, and deliberately so: it is where a reader checks a signature they
were handed, in their own browser, and a second implementation of the protocol
is worth more there than anywhere else.

### Certificates

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

Issuing and publishing them is `trust-cert`:

```bash
export TRUST_SERVER=https://trust.merten.dev
trust-cert issue Init.Data.Nat.Gcd Nat.gcd -o gcd.json
trust-cert sign gcd.json
trust-cert publish gcd.json
```

What this library provides is the part both ends have to agree on: the claim
types, the canonical bytes a signature covers, and `Trust.Federation`, which is
`FEDERATION.md`'s acceptance rules as code.  `trust-cert verify-bundle` and a
node's import path call the same function, which is what makes "repeat the check
the server claims to have done" a fact about the code rather than a promise.

### Federation

There is no central trust database.  A server is a *node*: it holds the
certificates published to it, learns others from the nodes it talks to, and
passes on questions it cannot answer.  The protocol is
[FEDERATION.md](FEDERATION.md), and it is written as a protocol rather than as
documentation of an implementation because the point of federating is that the
other end is not this code.

Three consequences worth stating here, since they shape everything above:

* **Only signed certificates federate.**  `attested` means "a signed-in account
  said so, and this server vouches for that", which is not something a third
  party can check or repeat — so it stays where it was made.
* **Identity across a boundary is a key fingerprint**, not a login.  Names
  travel as unverified hints and are shown as such.
* **Trust is not transitive.**  Trusting someone counts their certificates and
  nobody else's.

### Conformance

`conformance/` is the contract between this implementation and the browser's:
the canonical form of a claim and of a revocation, a node descriptor, an entry
that must be accepted, and one entry for each way §3.4 says to refuse.

```bash
./.lake/build/bin/trust conformance --check      # against the committed vectors
./.lake/build/bin/trust conformance --out conformance   # regenerate them
```

They are generated rather than written, because a vector that was typed says
what somebody thought the implementation did.  The one worth reading is
`fingerprint-is-the-subkey`: gpg signs with a subkey, so that entry has a valid
signature and names a fingerprint that really is in the key bundle, and must
still be refused, because rule 3 asks for the primary.  An implementation that
confuses those two passes every other vector in the file.

## Tests

```bash
lake test
```

Timestamps, the canonical bytes, the address rules of §5.4, the protocol's
decisions, and acceptance against real gpg keys with real signing subkeys.  The
signature tests skip loudly when `gpg` is absent rather than passing quietly — a
suite that reports success because it did nothing is worse than one that fails.

## License

[Apache License 2.0](LICENSE).
