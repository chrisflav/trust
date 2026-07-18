import Lean
import Trust.Graph
import Trust.Marks
import SemanticHash

/-!
# Fingerprinting a declaration's content

A protected declaration is one whose content is watched, so `trust` has to be
able to say whether it is still the same declaration it was at an earlier
commit.  That needs a fingerprint.

The fingerprint we actually want is a *semantic* hash — one that is stable under
changes that do not change meaning, such as renaming a binder or reordering
independent hypotheses.  That is what
[semantic_hash](https://github.com/mathlib-initiative/semantic_hash) computes,
and it is the intended implementation.  It currently builds against Lean
v4.30.0 while `trust` is on v4.31.0, so it cannot be depended on yet.

So hashing goes through a `Hasher` record rather than being called directly, and
the default is a structural hash.  Swapping in `semantic_hash` later means
adding one `Hasher` and changing the default; nothing else in the codebase
learns about it.  Every recorded snapshot carries the name of the hasher that
produced it, because hashes from different hashers are not comparable and
silently comparing them would report changes that never happened.
-/

namespace Trust

open Lean

/--
A way of condensing a declaration's content into a comparable string.

`hash` returns none when the declaration is not in the environment.
-/
structure Hasher where
  /-- Identifier recorded alongside every hash this produces. -/
  name : String
  /-- Fingerprint a declaration. -/
  hash : Environment → Name → IO (Option String)

/-- Render a `UInt64` as fixed-width hex, so hashes sort and align. -/
def toHex (n : UInt64) : String :=
  let digits := String.ofList (Nat.toDigits 16 n.toNat)
  "".pushn '0' (16 - digits.length) ++ digits

/--
Mix two hashes.

`Expr.hash` alone would collide across a type/value pair as readily as it
distinguishes them, so the two are combined rather than added.
-/
def mixHash64 (a b : UInt64) : UInt64 :=
  mixHash a b

/--
The structural hash of a declaration: its type, its value, and its kind.

This is deliberately the conservative option.  It is stable for a fixed
toolchain and it never misses a real change, but it is *not* semantic: it
reports a change when a binder is renamed or a proof is rewritten, even though
the meaning is untouched.  For proofs that is arguably right — a changed proof
is a changed proof — but for statements it means false alarms that a semantic
hash would not raise.
-/
def structuralHasher : Hasher where
  name := "structural-v1"
  hash env declName := do
    match env.find? declName with
    | none => return none
    | some info =>
      let kindHash := hash (DeclKind.ofConstantInfo info).toString
      let typeHash := info.type.hash
      let valueHash :=
        match info.value? (allowOpaque := true) with
        | some v => v.hash
        | none =>
          -- An inductive type has no value; its constructors are its content,
          -- the same reading `Trust.Deps` takes when following dependencies.
          match info with
          | .inductInfo val =>
            val.ctors.foldl (init := (7 : UInt64)) fun acc ctor =>
              match env.find? ctor with
              | some c => mixHash64 acc (mixHash64 (hash ctor.toString) c.type.hash)
              | none => acc
          | _ => 0
      return some (toHex (mixHash64 kindHash (mixHash64 typeHash valueHash)))

/--
The semantic hash, from `semantic_hash`.

This is the one trust certificates are written against, because it is the only
one whose equality means anything to a *reader*: it is computed over the
definitional closure, so a declaration's hash incorporates the hashes of
everything it references, transitively.  Vouching for a hash therefore vouches
for the whole subtree beneath it, and any change in meaning underneath
invalidates the certificate on its own.

Deliberately blind to things that are not meaning:

* the declaration's own name — it never enters its hash, so a rename is invisible;
* the names of the constants it references — those contribute their *hashes*;
* binder names, and whether an argument is implicit or explicit;
* constructor names within an inductive family.

Those are `HashOptions`' defaults, which the on-demand path uses; `trust
hash-invariants` checks them against real declarations rather than trusting the
documentation.

One thing this is *not*: proof-irrelevant.  `runFor` hashes the dependency cone
on demand and is proof-relevant, so re-proving a lemma changes its hash even
though its statement is untouched — the proof-irrelevant variant exists but only
as a whole-environment pass.  For protection that is arguably right, a changed
proof being a changed proof; for certificates it is stricter than it needs to
be, and is worth revisiting once the certificate format is settled.  The name
records the choice so that hashes made under a different one are never compared
against these.
-/
def semanticHasher : Hasher where
  name := "semantic-v1"
  hash env declName := do
    if (env.find? declName).isNone then return none
    let hashes ← SemanticHash.Hashing.runFor env #[declName]
    return (hashes[declName]?).map toHex

/-- The hasher used unless another is chosen. -/
def defaultHasher : Hasher := semanticHasher

/-- What checking a protected declaration turned up. -/
inductive ProtectionStatus where
  /-- Content matches the most recent snapshot. -/
  | unchanged
  /-- Content differs from the most recent snapshot. -/
  | changed (recorded : String) (current : String) (commit : String)
  /-- Protected, but no snapshot has been recorded yet. -/
  | unrecorded
  /-- The declaration is no longer in the environment. -/
  | missing
  /-- The latest snapshot came from a different hasher, so cannot be compared. -/
  | incomparable (recorded : String)
  deriving Inhabited, Repr

/-- Whether a status is one the user needs to be told about. -/
def ProtectionStatus.isWarning : ProtectionStatus → Bool
  | .changed .. | .missing | .incomparable _ => true
  | .unchanged | .unrecorded => false

/-- The wire form, so the frontend can show the same verdict. -/
def ProtectionStatus.toString : ProtectionStatus → String
  | .unchanged => "unchanged"
  | .changed .. => "changed"
  | .unrecorded => "unrecorded"
  | .missing => "missing"
  | .incomparable _ => "incomparable"

/-- A human-readable account of a status, for the CLI. -/
def ProtectionStatus.describe (name : String) : ProtectionStatus → String
  | .unchanged => s!"ok       {name}"
  | .unrecorded => s!"new      {name}: protected but never snapshotted; run `trust protect` to record"
  | .missing => s!"MISSING  {name}: protected but not present in this environment"
  | .incomparable h => s!"SKIPPED  {name}: last snapshot came from hasher `{h}`"
  | .changed recorded current commit =>
    s!"CHANGED  {name}: {recorded} at {commit} → {current} now"

/-- Compare a protected declaration against its most recent snapshot. -/
def checkProtected (env : Environment) (hasher : Hasher) (entry : ProtectedMark) :
    IO ProtectionStatus := do
  match ← hasher.hash env entry.name.toName with
  | none => return .missing
  | some current =>
    match entry.latest? with
    | none => return .unrecorded
    | some snapshot =>
      if !snapshot.hasher.isEmpty && snapshot.hasher != hasher.name then
        return .incomparable snapshot.hasher
      else if snapshot.hash == current then
        return .unchanged
      else
        return .changed snapshot.hash current snapshot.commit

/--
Check every protected declaration.

This is the function an environment linter would wrap: it takes an environment
and reports per declaration, with no IO of its own beyond hashing.
-/
def checkAllProtected (env : Environment) (hasher : Hasher) (marks : Marks) :
    IO (Array (String × ProtectionStatus)) := do
  let mut out := #[]
  for entry in marks.protectedDecls do
    out := out.push (entry.name, ← checkProtected env hasher entry)
  return out

end Trust
