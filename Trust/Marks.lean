import Lean

/-!
# Human judgements about declarations

Everything else in `trust` is derived: the dependency graph, the rendered code
and the axioms all fall out of the environment, and re-running the exporter
reproduces them exactly.  The marks in this file are the opposite — they are
what a person decided, and nothing can recompute them.

So they live in a JSON file of their own, version-controlled alongside the code
rather than inside a generated index, and every mark records the commit it was
made at.  A judgement about a declaration is only worth anything if you know
which version of that declaration it was made about.

Three kinds of mark, all from `DESIGN.md`:

* **trusted** — someone vouched for this declaration at a commit;
* **characterized** — this definition is pinned down by these theorems, which is
  what lets a dependency tree stop at it and continue through them instead;
* **protected** — this declaration's content is watched, and a snapshot of its
  hash is kept per commit so that a later change can be reported.
-/

namespace Trust

open Lean

/-- Default location of the marks file, relative to the working directory. -/
def marksFileName : String := "trust-marks.json"

/-- Someone vouched for a declaration, at a particular commit. -/
structure TrustMark where
  /-- Fully qualified declaration name. -/
  name : String
  /-- Revision the judgement was made at. -/
  commit : String := ""
  /-- Why, in the marker's own words. -/
  note : String := ""
  deriving Inhabited, Repr

/--
A definition together with the theorems that pin it down.

`DESIGN.md` asks that a characterized definition's dependency tree be cut off
and replaced by the characterising theorems: what you have to trust about
`Finset` is not how it is built out of `Multiset`, but that it behaves the way
`Finset.ext` says it does.
-/
structure Characterization where
  /-- The definition being characterized. -/
  definition : String
  /-- Theorems that together characterize it. -/
  theorems : Array String := #[]
  /-- Why these theorems are held to be a complete characterization. -/
  note : String := ""
  deriving Inhabited, Repr

/-- What a declaration hashed to at one commit. -/
structure HashSnapshot where
  /-- Revision the snapshot was taken at. -/
  commit : String
  /-- Fingerprint of the declaration's content. -/
  hash : String
  /-- Which hasher produced it; hashes are only comparable within one. -/
  hasher : String := ""
  deriving Inhabited, Repr

/-- A declaration whose content is watched for change. -/
structure ProtectedMark where
  /-- Fully qualified declaration name. -/
  name : String
  /-- Why this declaration is worth watching. -/
  note : String := ""
  /-- Hashes recorded over time, oldest first. -/
  snapshots : Array HashSnapshot := #[]
  deriving Inhabited, Repr

/-- The whole marks file. -/
structure Marks where
  /-- Schema version of the file. -/
  version : Nat := 1
  /-- Declarations someone has vouched for. -/
  trusted : Array TrustMark := #[]
  /-- Definitions pinned down by theorems. -/
  characterizations : Array Characterization := #[]
  /-- Declarations watched for content changes. -/
  protectedDecls : Array ProtectedMark := #[]
  deriving Inhabited, Repr

/-- A string field, falling back when absent so that hand-edited files load. -/
private def strField (j : Json) (key : String) (fallback : String := "") : String :=
  match j.getObjValAs? String key with
  | .ok s => s
  | .error _ => fallback

/-- An array field, read through `f`, treating an absent key as empty. -/
private def arrayField (j : Json) (key : String) (f : Json → Except String α) :
    Except String (Array α) :=
  match j.getObjVal? key with
  | .error _ => .ok #[]
  | .ok value =>
    match value.getArr? with
    | .error _ => .ok #[]
    | .ok items => items.foldlM (init := #[]) fun out item => return out.push (← f item)

instance : ToJson TrustMark where
  toJson m := Json.mkObj [("name", m.name), ("commit", m.commit), ("note", m.note)]

instance : FromJson TrustMark where
  fromJson? j := do
    let name := strField j "name"
    if name.isEmpty then throw "trust mark is missing `name`"
    return { name, commit := strField j "commit", note := strField j "note" }

instance : ToJson Characterization where
  toJson c := Json.mkObj [
    ("definition", c.definition),
    ("theorems", toJson c.theorems),
    ("note", c.note)]

instance : FromJson Characterization where
  fromJson? j := do
    let definition := strField j "definition"
    if definition.isEmpty then throw "characterization is missing `definition`"
    let theorems ← arrayField j "theorems" fun t => t.getStr?
    return { definition, theorems, note := strField j "note" }

instance : ToJson HashSnapshot where
  toJson s := Json.mkObj [("commit", s.commit), ("hash", s.hash), ("hasher", s.hasher)]

instance : FromJson HashSnapshot where
  fromJson? j :=
    return { commit := strField j "commit", hash := strField j "hash",
             hasher := strField j "hasher" }

instance : ToJson ProtectedMark where
  toJson p := Json.mkObj [
    ("name", p.name),
    ("note", p.note),
    ("snapshots", toJson p.snapshots)]

instance : FromJson ProtectedMark where
  fromJson? j := do
    let name := strField j "name"
    if name.isEmpty then throw "protected mark is missing `name`"
    let snapshots ← arrayField j "snapshots" fun s => fromJson? s
    return { name, note := strField j "note", snapshots }

instance : ToJson Marks where
  toJson m := Json.mkObj [
    ("version", toJson m.version),
    ("trusted", toJson m.trusted),
    ("characterizations", toJson m.characterizations),
    ("protected", toJson m.protectedDecls)]

instance : FromJson Marks where
  fromJson? j := do
    let version := (j.getObjValAs? Nat "version").toOption.getD 1
    let trusted ← arrayField j "trusted" fun t => fromJson? t
    let characterizations ← arrayField j "characterizations" fun c => fromJson? c
    let protectedDecls ← arrayField j "protected" fun p => fromJson? p
    return { version, trusted, characterizations, protectedDecls }

/-- Read the marks file, treating a missing file as no marks at all. -/
def Marks.load (path : System.FilePath) : IO Marks := do
  if !(← path.pathExists) then
    return {}
  let text ← IO.FS.readFile path
  if text.trimAscii.isEmpty then
    return {}
  match Json.parse text >>= fromJson? with
  | .ok marks => return marks
  | .error msg => throw <| IO.userError s!"{path}: {msg}"

/--
Write the marks file.

Pretty-printed and with the entries in name order: this file is meant to be
read, reviewed and merged by people, so a stable layout matters more than a
compact one.
-/
def Marks.save (marks : Marks) (path : System.FilePath) : IO Unit := do
  let byName (a b : String) : Bool := a < b
  let sorted : Marks := {
    marks with
    trusted := marks.trusted.qsort fun a b => byName a.name b.name
    characterizations := marks.characterizations.qsort fun a b => byName a.definition b.definition
    protectedDecls := marks.protectedDecls.qsort fun a b => byName a.name b.name }
  IO.FS.writeFile path ((toJson sorted).pretty ++ "\n")

/-- The trust mark for a declaration, if there is one. -/
def Marks.trustOf? (marks : Marks) (name : String) : Option TrustMark :=
  marks.trusted.find? fun m => m.name == name

/-- The characterization of a definition, if there is one. -/
def Marks.characterizationOf? (marks : Marks) (name : String) : Option Characterization :=
  marks.characterizations.find? fun c => c.definition == name

/-- The protection entry for a declaration, if there is one. -/
def Marks.protectionOf? (marks : Marks) (name : String) : Option ProtectedMark :=
  marks.protectedDecls.find? fun p => p.name == name

/-- The most recently recorded snapshot, which is the one to compare against. -/
def ProtectedMark.latest? (p : ProtectedMark) : Option HashSnapshot :=
  p.snapshots.back?

/-- Replace the entry for `name`, or append when there is none. -/
def upsert (entries : Array α) (name : α → String) (key : String) (entry : α) : Array α :=
  match entries.findIdx? fun e => name e == key with
  | some i => entries.set! i entry
  | none => entries.push entry

/--
The revision of the repository `trust` is being run in.

Marks are only meaningful against a version of the code, and the version the
user means is almost always "the one checked out right now", so it is read from
git rather than asked for.  An empty string when this is not a git checkout;
that is recorded honestly rather than guessed at.
-/
def currentCommit : IO String := do
  try
    let out ← IO.Process.output { cmd := "git", args := #["rev-parse", "--short", "HEAD"] }
    if out.exitCode == 0 then return out.stdout.trimAscii.toString else return ""
  catch _ =>
    return ""

end Trust
