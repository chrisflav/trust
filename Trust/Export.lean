import Lean
import AFTK
import Trust.Graph
import Trust.Deps
import Trust.Code
import Trust.Marks
import Trust.Hash

/-!
# Bulk export

The frontend is a static site, so the whole index is precomputed once per
repository and per revision.  We export the **direct** edge relation only:
per-declaration transitive closures would be quadratic in the size of the
library, while both dependency directions are a cheap breadth-first search over
the direct relation once it is loaded in the browser.

Statement edges are always written.  Body edges — which are far more numerous,
since they include every constant used in every proof term — are opt-in.
-/

namespace Trust

open Lean

/-- Options for a bulk export run. -/
structure ExportConfig where
  /-- Repository name, used as the output subdirectory and as node provenance. -/
  repo : String
  /-- Revision of the repository, recorded in `meta.json`. -/
  rev : String := ""
  /-- Directory to write the index into. -/
  outDir : System.FilePath
  /-- Restrict exported declarations to matching modules.  Empty means all. -/
  filter : AFTK.ModuleFilter := {}
  /-- Also export body edges, i.e. dependencies arising from proof terms. -/
  withBodies : Bool := false
  /-- Skip `MetaM` `Prop` checks, treating exactly the theorems as proofs. -/
  fastProp : Bool := false
  /-- Also export rendered, clickable source for every declaration. -/
  withCode : Bool := false
  /-- Marks file to carry into the index, so the frontend can show judgements. -/
  marksPath : String := marksFileName
  deriving Inhabited

/--
Append a 32-bit little-endian integer.

Edges are written as raw `(src, tgt)` pairs rather than JSON lines.  A browser
can map the result straight onto an `Int32Array` with no parsing at all; the
JSON form cost 28 MB of text and over a million transient line strings for Lean
core alone, which was enough to exhaust memory in Firefox.
-/
def pushInt32LE (buf : ByteArray) (n : Nat) : ByteArray :=
  buf.push (UInt8.ofNat (n % 256))
    |>.push (UInt8.ofNat (n / 256 % 256))
    |>.push (UInt8.ofNat (n / 65536 % 256))
    |>.push (UInt8.ofNat (n / 16777216 % 256))

/-- Flush an edge buffer to disk once it grows past this many bytes. -/
def edgeFlushBytes : Nat := 1 <<< 20

/--
Declarations per rendered-code shard.

Rendered code is far too large to ship as one file, and the frontend only ever
needs the declaration the user is looking at.  Ids are assigned in module
traversal order, so a contiguous id range is also roughly a coherent group of
modules; sharding on `id / codeShardSize` therefore needs no lookup table on
either side — the shard is computed from the id.
-/
def codeShardSize : Nat := 2000

/-- Every displayable declaration in the environment accepted by the filter. -/
def exportedDeclarations (env : Environment) (filter : AFTK.ModuleFilter) : Array Name := Id.run do
  let mut out := #[]
  for _h : idx in [0:env.header.modules.size] do
    let moduleName := env.header.modules[idx].module
    if filter.accepts moduleName then
      for info in env.header.moduleData[idx]!.constants do
        if AFTK.shouldDisplay env info.name then
          out := out.push info.name
  return out

/-- Whether a declaration is a proof, honouring `fastProp`. -/
def isProofFor (env : Environment) (config : ExportConfig) (declName : Name) :
    StateRefT PropCache IO Bool :=
  if config.fastProp then
    return match env.find? declName with
      | some info => info.isTheorem
      | none => false
  else
    isProof env declName

/--
The marks, as the frontend receives them.

Protection is resolved here rather than in the browser: deciding whether a
declaration still matches its snapshot needs the environment, which only the
exporter has.  The browser is handed the verdict.
-/
def exportedMarksJson (marks : Marks) (hasher : Hasher)
    (statuses : Array (String × ProtectionStatus)) : Json :=
  let protectedJson := marks.protectedDecls.map fun entry =>
    let status := (statuses.find? fun (name, _) => name == entry.name).map Prod.snd
      |>.getD ProtectionStatus.unrecorded
    let base := [
      ("name", Json.str entry.name),
      ("note", Json.str entry.note),
      ("status", Json.str status.toString)]
    let detail :=
      match status with
      | .changed recorded current commit =>
        [("recordedHash", Json.str recorded),
         ("currentHash", Json.str current),
         ("recordedAt", Json.str commit)]
      | _ => []
    Json.mkObj (base ++ detail)
  Json.mkObj [
    ("version", toJson marks.version),
    ("hasher", Json.str hasher.name),
    ("trusted", toJson marks.trusted),
    ("characterizations", toJson marks.characterizations),
    ("protected", Json.arr protectedJson)]

/-- Whether a marks file carries anything at all. -/
def Marks.isEmpty (marks : Marks) : Bool :=
  marks.trusted.isEmpty && marks.characterizations.isEmpty && marks.protectedDecls.isEmpty

/--
Write an index's `marks.json`, resolving each protected declaration's status.

Separate from the rest of the export because marks change on a completely
different timescale from the graph: the declarations move when the repository
does, but a judgement can be recorded any minute of the day.  Re-exporting
Mathlib to record one is twenty-five minutes; refreshing this file is seconds,
and it is the only part of an index that a human edits.

Returns whether anything was written.
-/
def writeMarks (env : Environment) (dir : System.FilePath) (marksPath : System.FilePath) :
    IO Bool := do
  let marks ← Marks.load marksPath
  if marks.isEmpty then
    return false
  let statuses ← checkAllProtected env defaultHasher marks
  IO.FS.writeFile (dir / "marks.json")
    ((exportedMarksJson marks defaultHasher statuses).pretty ++ "\n")
  let needing := statuses.filter fun (_, status) => status.isWarning
  IO.eprintln s!"trust: carried {marks.trusted.size} trusted, \
{marks.characterizations.size} characterized, {marks.protectedDecls.size} protected \
({needing.size} needing attention)"
  return true

/-- Run a bulk export, writing `meta.json`, `decls.jsonl` and the edge files. -/
def runExport (env : Environment) (config : ExportConfig) : IO Unit := do
  let dir := config.outDir / config.repo
  IO.FS.createDirAll dir
  let declarations := exportedDeclarations env config.filter
  IO.eprintln s!"trust: exporting {declarations.size} declarations from `{config.repo}`"

  -- Ids are indices into the declaration table, assigned in traversal order.
  let mut ids : Std.HashMap Name Nat := {}
  for h : i in [0:declarations.size] do
    ids := ids.insert declarations[i] i

  let declHandle ← IO.FS.Handle.mk (dir / "decls.jsonl") .write
  let stmtHandle ← IO.FS.Handle.mk (dir / "stmt-edges.bin") .write
  let bodyHandle ← IO.FS.Handle.mk (dir / "body-edges.bin") .write
  if config.withCode then
    IO.FS.createDirAll (dir / "code")

  let write : StateRefT PropCache IO (Nat × Nat) := do
    let mut stmtEdges := 0
    let mut bodyEdges := 0
    let mut stmtBuf : ByteArray := .empty
    let mut bodyBuf : ByteArray := .empty
    -- Shards are written sequentially: ids ascend, so the shard only ever
    -- advances and one open handle at a time is enough.
    let mut codeHandle : Option IO.FS.Handle := none
    let mut codeShard := 0
    for h : i in [0:declarations.size] do
      let declName := declarations[i]
      if i % 20000 == 0 && i > 0 then
        IO.eprintln s!"trust: {i}/{declarations.size}"
      if config.withCode then
        let shard := i / codeShardSize
        if codeHandle.isNone || shard != codeShard then
          codeHandle := some (← IO.FS.Handle.mk (dir / "code" / s!"{shard}.jsonl") .write)
          codeShard := shard
        -- One bad declaration must not abort a whole export run.
        let code ← try declCode env i declName catch _ =>
          pure { id := i, signature := { text := s!"{privateToUserName declName}" } }
        if let some handle := codeHandle then
          handle.putStrLn (Json.compress (toJson code))
      let isProp ← isProofFor env config declName
      let kind :=
        match env.find? declName with
        | some info => DeclKind.ofConstantInfo info
        | none => .ax
      let node : Node :=
        { id := i
          name := s!"{privateToUserName declName}"
          module := s!"{AFTK.moduleOfD env declName}"
          kind
          isProp
          isData := !isProp }
      declHandle.putStrLn (Json.compress (toJson node))
      for dep in displayableSuccessors env (statementConstants env) declName do
        if let some tgt := ids[dep]? then
          stmtBuf := pushInt32LE (pushInt32LE stmtBuf i) tgt
          stmtEdges := stmtEdges + 1
          if stmtBuf.size ≥ edgeFlushBytes then
            stmtHandle.write stmtBuf
            stmtBuf := .empty
      -- A proof's body is never walked, in either direction: what a proof term
      -- happens to mention is not something the theorem rests on, only the
      -- statement is.  Writing those edges anyway cost 89% of this file for
      -- data no reader of the index can reach.
      if config.withBodies && !isProp then
        for dep in displayableSuccessors env (bodyConstants env) declName do
          if let some tgt := ids[dep]? then
            bodyBuf := pushInt32LE (pushInt32LE bodyBuf i) tgt
            bodyEdges := bodyEdges + 1
            if bodyBuf.size ≥ edgeFlushBytes then
              bodyHandle.write bodyBuf
              bodyBuf := .empty
    stmtHandle.write stmtBuf
    bodyHandle.write bodyBuf
    return (stmtEdges, bodyEdges)
  let ((stmtEdges, bodyEdges), _) ← write.run {}

  -- Marks are human judgements about these declarations; the index carries them
  -- so that the frontend can show them without a second source of truth.  Their
  -- presence is not also recorded in `meta.json`: whether the file is there is
  -- the fact, and `trust sync-marks` can write it long after this ran, so a flag
  -- alongside it would only be something else to go stale.
  let _ ← writeMarks env dir config.marksPath

  -- A mark is a judgement about a declaration *as it was at some revision*, and
  -- the revision that matters is the indexed repository's, not `trust`'s.  The
  -- export runs inside that repository, so read it from git when it was not
  -- given explicitly; otherwise every mark made from the browser is unpinned.
  let rev ← if config.rev.isEmpty then currentCommit else pure config.rev

  let metaJson := Json.mkObj [
    ("schemaVersion", (1 : Nat)),
    ("repo", config.repo),
    ("rev", rev),
    ("toolchain", Lean.versionString),
    ("moduleCount", env.header.modules.size),
    ("declCount", declarations.size),
    ("stmtEdgeCount", stmtEdges),
    ("bodyEdgeCount", bodyEdges),
    ("hasBodyEdges", config.withBodies),
    ("hasCode", config.withCode),
    ("codeShardSize", codeShardSize),
    -- Edge files are flat little-endian int32 (src, tgt) pairs.
    ("edgeFormat", "i32le")
  ]
  IO.FS.writeFile (dir / "meta.json") (metaJson.pretty ++ "\n")
  IO.eprintln s!"trust: wrote {declarations.size} declarations, {stmtEdges} statement edges, \
{bodyEdges} body edges to {dir}"

end Trust