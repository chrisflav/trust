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

Hashing goes through a `Hasher` (`Trust/Hash.lean`).  The intended
implementation is [semantic_hash](https://github.com/mathlib-initiative/semantic_hash),
which is stable under changes that do not change meaning; it currently builds
against Lean v4.30.0 while `trust` is on v4.31.0, so the default for now is a
structural hash that never misses a real change but does report renamed binders
as changes.  Every snapshot records which hasher produced it, and hashes from
different hashers are reported as incomparable rather than silently diffed.

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
cd web && npm test
```

The frontend suite includes a check against a real exported index, which is
skipped when none has been generated.

## License

[Apache License 2.0](LICENSE).
