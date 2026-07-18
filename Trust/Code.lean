import Lean
import AFTK
import Trust.Graph
import Trust.Deps

/-!
# Rendering declarations as clickable code

`DESIGN.md` asks for syntax-highlighted declarations — without the proof body for
theorems, with the body for definitions — in which clicking a constant focuses
that declaration.

The clickable half has to come from Lean: only the delaborator knows which
constant a rendered token actually refers to, once notation, coercions and
instances have been resolved.  `PrettyPrinter.ppSignature` returns a `Format`
together with an `InfoPerPos` map, and `TaggedText.prettyTagged` turns that into
a tree whose tags index into the map.  Walking that tree yields character ranges
paired with constant names, which is exactly what the frontend needs.

Token colouring is *not* done here: it is cosmetic, it needs no environment, and
doing it in the frontend keeps the exported data smaller.

Note that source code is never consulted.  A declaration read from an `.olean`
has no syntax, so what is rendered is the delaborated term, not the text the
author originally wrote.
-/

namespace Trust

open Lean PrettyPrinter Widget

/-- A reference from a range of rendered code to the constant it denotes. -/
structure CodeRef where
  /-- Start offset, in UTF-16 code units. -/
  start : Nat
  /-- End offset, exclusive, in UTF-16 code units. -/
  stop : Nat
  /-- The constant the range refers to. -/
  name : String
  deriving Inhabited, ToJson, FromJson

/-- A block of rendered code together with its constant references. -/
structure CodeBlock where
  /-- The rendered text. -/
  text : String
  /-- Ranges within `text` that refer to constants. -/
  refs : Array CodeRef := #[]
  deriving Inhabited, ToJson, FromJson

/-- The rendered form of one declaration. -/
structure DeclCode where
  /-- Node id, matching the declaration table of the index. -/
  id : Nat
  /-- The signature: `def Nat.gcd (m n : Nat) : Nat`. -/
  signature : CodeBlock
  /-- The body, for data-carrying declarations only.  Proofs are omitted. -/
  value : Option CodeBlock := none
  /--
  The declaration's docstring, when it has one.

  Carried in the code shard rather than in `decls.jsonl`: docstrings are prose
  and only the declaration on screen needs one, so they belong with the rendered
  source that is already fetched on demand rather than in the table that is
  loaded in full at startup.
  -/
  doc : Option String := none
  deriving Inhabited, ToJson, FromJson

/--
Length of a string in UTF-16 code units.

JavaScript string offsets are UTF-16 code units, while Lean counts codepoints.
The two agree only below U+10000, and mathematical alphanumerics such as `𝔽` —
which do occur in Mathlib — sit above it, so counting codepoints here would
silently misplace every reference after the first such character.
-/
def utf16Length (s : String) : Nat :=
  s.foldl (fun n c => n + if c.val ≥ 0x10000 then 2 else 1) 0

/-- The constant an info node denotes, if it denotes one. -/
def constOfInfo? : Elab.Info → Option Name
  | .ofTermInfo info =>
    match info.expr with
    | .const declName _ => some declName
    | _ => none
  | .ofDelabTermInfo info =>
    match info.toTermInfo.expr with
    | .const declName _ => some declName
    | _ => none
  | _ => none

/-- Accumulator for flattening tagged text into a string plus reference ranges. -/
private structure FlattenState where
  text : String := ""
  offset : Nat := 0
  refs : Array CodeRef := #[]

/--
Flatten tagged text, recording a reference for every tag that denotes a constant.

Tags nest — the tag for an application encloses the tag for its head constant —
but only the constant-denoting ones produce references, so nesting resolves
itself in practice.
-/
private partial def flatten (infos : InfoPerPos) (tt : TaggedText (Nat × Nat)) :
    StateM FlattenState Unit := do
  match tt with
  | .text s =>
    modify fun st => { st with text := st.text ++ s, offset := st.offset + utf16Length s }
  | .append parts =>
    for part in parts do
      flatten infos part
  | .tag (pos, _) sub =>
    let before ← get
    flatten infos sub
    let after ← get
    if let some info := infos.get? pos then
      if let some declName := constOfInfo? info then
        -- The delaborator pads notation tokens with the surrounding whitespace,
        -- so `Ne` arrives as " ≠ ".  Clicking should not extend into the gaps.
        let produced := (after.text.drop before.text.length).toString
        let start := before.offset + (utf16Length produced - utf16Length produced.trimLeft)
        let stop := after.offset - (utf16Length produced - utf16Length produced.trimRight)
        if stop > start then
          modify fun st =>
            { st with refs := st.refs.push { start, stop, name := s!"{privateToUserName declName}" } }

/--
Keep only the innermost reference at each place.

With `pp.tagAppFns` an application is tagged both as a whole and on its head, so
`n.succ ≠ 0` yields a reference to `Ne` spanning the entire expression as well as
one spanning just `≠`.  Making the whole expression clickable as `Ne` would be
wrong, so any reference that strictly contains another is dropped.

References are sorted by start position, which lets the containment scan stop as
soon as it passes the end of the reference being tested.
-/
def pruneNestedRefs (refs : Array CodeRef) : Array CodeRef := Id.run do
  let sorted := refs.qsort fun a b => a.start < b.start || (a.start == b.start && a.stop < b.stop)
  let mut out := #[]
  for h : i in [0:sorted.size] do
    let ref := sorted[i]
    let mut contains := false
    for j in [0:sorted.size] do
      let other := sorted[j]!
      if other.start ≥ ref.stop then
        break
      if j != i && ref.start ≤ other.start && other.stop ≤ ref.stop &&
          (other.start != ref.start || other.stop != ref.stop) then
        contains := true
        break
    if !contains then
      out := out.push ref
  return out

/-- Render a `Format` with infos into a code block, offset by a literal prefix. -/
def blockOfFormat (fwi : FormatWithInfos) (leading : String := "") (width : Nat := 100) : CodeBlock :=
  let tagged := TaggedText.prettyTagged fwi.fmt (w := width)
  let start : FlattenState := { text := leading, offset := utf16Length leading }
  let (_, st) := (flatten fwi.infos tagged).run start
  { text := st.text, refs := pruneNestedRefs st.refs }

/-- The keyword a declaration is introduced by, where one makes sense. -/
def kindKeyword : DeclKind → String
  | .ax => "axiom "
  | .defn => "def "
  | .thm => "theorem "
  | .opaq => "opaque "
  | .indt => "inductive "
  | .quot => ""
  | .ctor => ""
  | .recr => ""

/-- Bodies can be arbitrarily large; keep the exported index and the UI sane. -/
def maxValueLength : Nat := 20000

/--
Render an inductive type's constructors, which stand in for its body.

`ppSignature` renders a declaration, not a whole `inductive` block, so the
constructors are rendered one by one and joined in the shape Lean would write
them.  Each is laid out against the text accumulated so far, which is what
`blockOfFormat`'s `leading` argument is for: it makes the reference offsets come
out relative to the finished block rather than to each constructor.
-/
def constructorBlock (val : InductiveVal) : MetaM CodeBlock := do
  let mut text := ""
  let mut refs : Array CodeRef := #[]
  for ctor in val.ctors do
    let leading := text ++ (if text.isEmpty then "  | " else "\n  | ")
    let block ←
      try
        let fwi ← ppSignature ctor
        pure (blockOfFormat fwi leading)
      catch _ =>
        pure { text := leading ++ s!"{privateToUserName ctor}", refs := #[] }
    text := block.text
    refs := refs ++ block.refs
  return { text, refs }

/-- Render a declaration's signature and, when it carries data, its body. -/
def declCodeFor (id : Nat) (declName : Name) : MetaM DeclCode := do
  let env ← getEnv
  let info := env.find? declName
  let kind := match info with
    | some info => DeclKind.ofConstantInfo info
    | none => .ax
  let signature ← do
    try
      let fwi ← ppSignature declName
      pure (blockOfFormat fwi (kindKeyword kind))
    catch _ =>
      pure { text := s!"{kindKeyword kind}{privateToUserName declName}" }
  -- Only data-carrying declarations show a body; a theorem's proof is omitted,
  -- which is what `DESIGN.md` asks for and also what keeps the export small.
  let value ← do
    match info with
    | none => pure none
    | some info =>
      if ← Meta.isProp info.type then
        pure none
      else
        match info with
        -- An inductive type has no value; its constructors are its content.
        | .inductInfo val =>
          try
            let block ← constructorBlock val
            if utf16Length block.text > maxValueLength then
              pure (some { text := "-- constructors omitted: too large", refs := #[] })
            else
              pure (some block)
          catch _ =>
            pure none
        | _ =>
        match info.value? (allowOpaque := true) with
        | none => pure none
        | some v =>
          try
            let fwi ← ppExprWithInfos v
            let block := blockOfFormat fwi
            if utf16Length block.text > maxValueLength then
              pure (some { text := "-- body omitted: too large", refs := #[] })
            else
              pure (some block)
          catch _ =>
            pure none
  -- Written by the author rather than derived from the term, so it says what
  -- the declaration is *for*, which nothing else in the index records.
  let doc ← try findDocString? env declName catch _ => pure none
  return { id, signature, value, doc }

/--
Render a declaration, tagging the head constants of applications too.

Without `pp.tagAppFns` the delaborator only tags whole applications, so `Nat.gcd
m n` would offer nothing to click on; with it, the function itself is tagged.
-/
def declCode (env : Environment) (id : Nat) (declName : Name) : IO DeclCode :=
  runMetaM env <| withOptions (fun opts => opts.setBool `pp.tagAppFns true) <|
    declCodeFor id declName

end Trust