import Lean
import AFTK
import Trust.Graph
import Trust.Deps
import Trust.Reverse
import Trust.Export
import Trust.Code
import Trust.Marks
import Trust.Hash
import Trust.Cert
import Trust.Serve
import Trust.Conformance

/-!
# Command line interface

`trust` is meant to be run *inside* a target repository so that the repository's
`LEAN_PATH` resolves its `.olean` files:

```bash
cd /path/to/mathlib4
lake env /path/to/trust/.lake/build/bin/trust deps Mathlib.Data.Nat.Defs Nat.gcd
```

Module filter syntax is deliberately `AFTK.ModulePattern`'s, so `--module`
behaves identically to `lake exe aftk`.
-/

namespace Trust

open Lean

/-- Top-level help text. -/
def helpText : String :=
"trust: definitional dependency analysis for Lean declarations.

Usage:
  trust deps [options] <module> <declaration>
  trust rdeps [options] <module> <declaration>
  trust decl <module> <declaration>
  trust export [options] <module>
  trust trusted [options] <module> <declaration>
  trust protect [options] <module> <declaration>
  trust characterize [options] <module> <definition> <theorem>...
  trust check [options] <module>
  trust sync-marks [options] <module>
  trust marks [options]
  trust conformance [--out <dir>] [--check]
  trust serve-marks [options] [<module>]
  trust hash-invariants <module>

Commands:
  deps          Definitional closure of a declaration's statement, as a JSON graph.
  rdeps         Declarations depending on a declaration, as a JSON graph.
  decl          Rendered declaration with clickable constant references, as JSON.
  export        Bulk-export a whole import closure as a static index.
  trusted       Record that a declaration is trusted, at the current commit.
  protect       Watch a declaration for change, recording a hash snapshot.
  characterize  Record that a definition is characterized by some theorems.
  check         Report protected declarations whose content has changed.
  sync-marks    Refresh an existing index's marks.json without re-exporting it.
  marks         Print the marks file.
  conformance   Write the protocol conformance vectors, or check them.
  serve-marks   Serve the marks file over HTTP, for the frontend's dev server.

Options for deps:
  --depth <n>          Bound expansion depth.  Default: unbounded.
  --no-axioms          Skip axiom collection for the root declaration.

Options for rdeps:
  -m, --module <pat>   Restrict output to matching modules.  Repeatable.
      --modules <pats> Comma-separated module patterns.
      --transitive     Report transitive rather than direct dependents.

Options for export:
  --out <dir>          Output directory.  Default: index.
  --repo <name>        Repository name, used as output subdirectory.  Required.
  --rev <rev>          Revision string recorded in meta.json.
  --marks <path>       Marks file to carry into the index.  Default: trust-marks.json.
  -m, --module <pat>   Restrict exported declarations to matching modules.
      --with-bodies    Also export body (proof-term) edges.
      --with-code      Also export rendered, clickable declaration source.
      --with-hashes    Also record each declaration's semantic hash, so the index
                       can be matched against trust certificates.
      --fast-prop      Treat exactly the theorems as proofs, skipping MetaM.

Options for trusted, protect, characterize, check and marks:
  --marks <path>       Marks file.  Default: trust-marks.json in the working directory.
  --note <text>        Note recorded alongside the mark.
  --commit <rev>       Record this revision instead of the checked-out one.
  --remove             Remove the mark rather than adding it.

Marks are human judgements — what someone decided, not what the environment
says — so they live in a version-controlled JSON file rather than in a generated
index, and each records the commit it was made at.  `check` exits non-zero when
a protected declaration has changed, so it can gate CI.

Certificates:
  Issuing, signing, publishing and checking certificates is `trust-cert`, from
  https://github.com/chrisflav/trust-cli.  It applies the same rules this
  binary does: `Trust.Federation` is in this library, and `trust-cert` calls it,
  so `trust-cert verify-bundle` repeats precisely the check a node claims to
  have done.

Module patterns:
  *        Match every module.
  A.B.C    Match exactly module A.B.C.
  A.B.*    Match A.B and everything below it.

Run trust inside the target repository via `lake env`, so that its oleans are on
LEAN_PATH.  Output is JSON on stdout; progress and errors go to stderr."

/-- Options accepted by `deps`. -/
structure DepsOptions where
  /-- Bound on expansion depth. -/
  depth : Option Nat := none
  /-- Whether to collect the root declaration's axioms. -/
  axioms : Bool := true

/-- Options accepted by `rdeps`. -/
structure RdepsOptions where
  /-- Output module restriction. -/
  filter : AFTK.ModuleFilter := {}
  /-- Report transitive rather than direct dependents. -/
  transitive : Bool := false

/-- Convert an `Except String` into an `IO` action. -/
def exceptToIO : Except String α → IO α
  | .ok a => pure a
  | .error msg => throw <| IO.userError msg

/-- Parse `deps` arguments. -/
def parseDeps (args : List String) : Except String (DepsOptions × String × String) :=
  go args {} #[]
where
  /-- Accumulate options and positional arguments. -/
  go (args : List String) (opts : DepsOptions) (positionals : Array String) :
      Except String (DepsOptions × String × String) :=
    match args with
    | [] =>
      if positionals.size == 2 then
        .ok (opts, positionals[0]!, positionals[1]!)
      else
        .error "expected <module> <declaration>"
    | "--depth" :: value :: rest =>
      match value.toNat? with
      | some n => go rest { opts with depth := some n } positionals
      | none => .error s!"invalid depth `{value}`"
    | "--no-axioms" :: rest => go rest { opts with axioms := false } positionals
    | arg :: rest =>
      if arg.startsWith "-" then
        .error s!"unknown option `{arg}`"
      else
        go rest opts (positionals.push arg)

/-- Parse `rdeps` arguments. -/
def parseRdeps (args : List String) : Except String (RdepsOptions × String × String) :=
  go args {} #[]
where
  /-- Accumulate options and positional arguments. -/
  go (args : List String) (opts : RdepsOptions) (positionals : Array String) :
      Except String (RdepsOptions × String × String) :=
    match args with
    | [] =>
      if positionals.size == 2 then
        .ok (opts, positionals[0]!, positionals[1]!)
      else
        .error "expected <module> <declaration>"
    | "--transitive" :: rest => go rest { opts with transitive := true } positionals
    | arg :: value :: rest =>
      if arg == "-m" || arg == "--module" || arg == "--modules" then
        match AFTK.parsePatternList value with
        | .ok patterns =>
          go rest { opts with filter := { patterns := opts.filter.patterns ++ patterns } }
            positionals
        | .error msg => .error msg
      else if arg.startsWith "-" then
        .error s!"unknown option `{arg}`"
      else
        go (value :: rest) opts (positionals.push arg)
    | arg :: rest =>
      if arg.startsWith "-" then
        .error s!"unknown option `{arg}`"
      else
        go rest opts (positionals.push arg)

/-- Parse `export` arguments. -/
def parseExport (args : List String) : Except String (ExportConfig × String) :=
  go args { repo := "", outDir := "index" } #[]
where
  /-- Accumulate options and positional arguments. -/
  go (args : List String) (config : ExportConfig) (positionals : Array String) :
      Except String (ExportConfig × String) :=
    match args with
    | [] =>
      if positionals.size != 1 then
        .error "expected <module>"
      else if config.repo.isEmpty then
        .error "missing required option `--repo`"
      else
        .ok (config, positionals[0]!)
    | "--with-bodies" :: rest => go rest { config with withBodies := true } positionals
    | "--fast-prop" :: rest => go rest { config with fastProp := true } positionals
    | "--with-code" :: rest => go rest { config with withCode := true } positionals
    | "--with-hashes" :: rest => go rest { config with withHashes := true } positionals
    | arg :: value :: rest =>
      if arg == "--out" then
        go rest { config with outDir := value } positionals
      else if arg == "--repo" then
        go rest { config with repo := value } positionals
      else if arg == "--rev" then
        go rest { config with rev := value } positionals
      else if arg == "--marks" then
        go rest { config with marksPath := value } positionals
      else if arg == "-m" || arg == "--module" || arg == "--modules" then
        match AFTK.parsePatternList value with
        | .ok patterns =>
          go rest { config with filter := { patterns := config.filter.patterns ++ patterns } }
            positionals
        | .error msg => .error msg
      else if arg.startsWith "-" then
        .error s!"unknown option `{arg}`"
      else
        go (value :: rest) config (positionals.push arg)
    | arg :: rest =>
      if arg.startsWith "-" then
        .error s!"unknown option `{arg}`"
      else
        go rest config (positionals.push arg)

/-- Options accepted by the commands that edit the marks file. -/
structure MarkOptions where
  /-- Where the marks file lives. -/
  marksPath : String := marksFileName
  /-- Note recorded with the mark. -/
  note : String := ""
  /-- Remove the mark rather than adding it. -/
  remove : Bool := false
  /-- Record this revision instead of the checked-out one. -/
  commit : String := ""
  /-- Repository a certificate claim is about. -/
  repo : String := ""
  /-- Where to write the result, when not stdout. -/
  out : String := ""
  /-- Which GPG key to sign with. -/
  key : String := ""
  /-- Certificate server base URL. -/
  server : String := ""
  /-- API token for the certificate server. -/
  token : String := ""
  /-- Which hasher a certificate query is about. -/
  hasher : String := ""
  /-- A node to read a bundle from, instead of a file. -/
  from? : String := ""
  /-- Port for `serve-marks`. -/
  port : Nat := 8123
  /-- Check the conformance vectors rather than writing them. -/
  check : Bool := false

/-- Parse the options shared by `trusted`, `protect`, `characterize` and `check`. -/
def parseMark (args : List String) : Except String (MarkOptions × Array String) :=
  go args {} #[]
where
  /-- Accumulate options and positional arguments. -/
  go (args : List String) (opts : MarkOptions) (positionals : Array String) :
      Except String (MarkOptions × Array String) :=
    match args with
    | [] => .ok (opts, positionals)
    | "--remove" :: rest => go rest { opts with remove := true } positionals
    | "--check" :: rest => go rest { opts with check := true } positionals
    | arg :: value :: rest =>
      if arg == "--marks" then go rest { opts with marksPath := value } positionals
      else if arg == "--note" then go rest { opts with note := value } positionals
      else if arg == "--commit" then go rest { opts with commit := value } positionals
      else if arg == "--repo" then go rest { opts with repo := value } positionals
      else if arg == "-o" || arg == "--out" then go rest { opts with out := value } positionals
      else if arg == "--key" then go rest { opts with key := value } positionals
      else if arg == "--server" then go rest { opts with server := value } positionals
      else if arg == "--token" then go rest { opts with token := value } positionals
      else if arg == "--hasher" then go rest { opts with hasher := value } positionals
      else if arg == "--from" then go rest { opts with from? := value } positionals
      else if arg == "--port" then go rest { opts with port := value.toNat!.max 1 } positionals
      else if arg.startsWith "-" then .error s!"unknown option `{arg}`"
      else go (value :: rest) opts (positionals.push arg)
    | arg :: rest =>
      if arg.startsWith "-" then .error s!"unknown option `{arg}`"
      else go rest opts (positionals.push arg)

/-- An environment variable, or a fallback when it is unset. -/
def envOr (name fallback : String) : IO String := do
  return (← IO.getEnv name).getD fallback

/-- Read and parse a certificate file, failing loudly rather than silently. -/
def readCertificate (path : String) : IO Certificate := do
  let text ← IO.FS.readFile path
  match Json.parse text >>= fromJson? with
  | .ok cert => return cert
  | .error msg => throw <| IO.userError s!"{path}: {msg}"

/--
A bundle, from a file or straight from a node.

`--from` fetches a node's public export, which needs no credentials: everything
in it is signed, and a signature is worth the same to a stranger as to a friend.
-/
def readBundle (opts : MarkOptions) (positionals : Array String) : IO (Except String Bundle) := do
  if !opts.from?.isEmpty then
    return ← fetchBundle opts.from? ""
  if positionals.size != 1 then
    return .error "expected <file>, or --from <node url>"
  let text ← IO.FS.readFile positionals[0]!
  match Json.parse text >>= fromJson? with
  | .ok bundle => return .ok bundle
  | .error msg => return .error s!"{positionals[0]!}: {msg}"

/--
The repository a claim is about, when it was not given.

The working directory's name: `trust` runs inside the repository it is talking
about, so that is nearly always the answer, and being wrong here is visible
rather than silent.
-/
def defaultRepoName : IO String := do
  let cwd ← IO.currentDir
  return cwd.fileName.getD "unknown"

/-- The revision to record: the one asked for, else the checked-out one. -/
def commitFor (opts : MarkOptions) : IO String :=
  if opts.commit.isEmpty then currentCommit else pure opts.commit

/-- Load a module's environment and resolve a declaration name inside it. -/
def loadAndResolve (moduleString declString : String) : IO (Environment × Name) := do
  let moduleName := moduleString.toName
  let env ← AFTK.loadModuleEnvironment moduleName
  let declName ← exceptToIO <| AFTK.resolveDeclaration env moduleName declString.toName
  return (env, declName)

/-- Run the CLI. -/
def run (args : List String) : IO UInt32 := do
  match args with
  | [] | ["--help"] | ["-h"] | ["help"] =>
    IO.println helpText
    return 0
  | "deps" :: rest =>
    match parseDeps rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, moduleString, declString) =>
      let (env, declName) ← loadAndResolve moduleString declString
      let graph ← definitionalClosure env declName opts.depth
      let graph ← if opts.axioms then withRootAxioms env declName graph else pure graph
      IO.println (Json.compress (toJson graph))
      return 0
  | "rdeps" :: rest =>
    match parseRdeps rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, moduleString, declString) =>
      let (env, declName) ← loadAndResolve moduleString declString
      let graph ← dependentsGraph env declName opts.filter opts.transitive
      IO.println (Json.compress (toJson graph))
      return 0
  | "decl" :: rest =>
    match rest with
    | [moduleString, declString] =>
      let (env, declName) ← loadAndResolve moduleString declString
      let code ← declCode env 0 declName
      IO.println (Json.compress (toJson code))
      return 0
    | _ =>
      IO.eprintln "error: expected <module> <declaration>"
      return 1
  | "export" :: rest =>
    match parseExport rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (config, moduleString) =>
      let env ← AFTK.loadModuleEnvironment moduleString.toName
      runExport env config
      return 0
  | "trusted" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, positionals) =>
      if positionals.size != 2 then
        IO.eprintln "error: expected <module> <declaration>"
        return 1
      let (_, declName) ← loadAndResolve positionals[0]! positionals[1]!
      let name := s!"{privateToUserName declName}"
      let marks ← Marks.load opts.marksPath
      if opts.remove then
        let marks := { marks with trusted := marks.trusted.filter fun m => m.name != name }
        marks.save opts.marksPath
        IO.eprintln s!"trust: {name} is no longer marked trusted"
      else
        let commit ← commitFor opts
        let entry : TrustMark := { name, commit, note := opts.note }
        let marks := { marks with trusted := upsert marks.trusted (·.name) name entry }
        marks.save opts.marksPath
        IO.eprintln s!"trust: {name} marked trusted at {commit}"
      return 0
  | "protect" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, positionals) =>
      if positionals.size != 2 then
        IO.eprintln "error: expected <module> <declaration>"
        return 1
      let (env, declName) ← loadAndResolve positionals[0]! positionals[1]!
      let name := s!"{privateToUserName declName}"
      let marks ← Marks.load opts.marksPath
      if opts.remove then
        let marks := { marks with
          protectedDecls := marks.protectedDecls.filter fun p => p.name != name }
        marks.save opts.marksPath
        IO.eprintln s!"trust: {name} is no longer protected"
        return 0
      let hasher := defaultHasher
      match ← hasher.hash env declName with
      | none =>
        IO.eprintln s!"error: {name} is not present in this environment"
        return 1
      | some current =>
        let commit ← commitFor opts
        let existing := (marks.protectionOf? name).getD { name }
        -- Re-protecting an unchanged declaration should not grow the history;
        -- a snapshot is only worth recording when it says something new.
        let snapshots :=
          match existing.latest? with
          | some last =>
            if last.hash == current && last.hasher == hasher.name then existing.snapshots
            else existing.snapshots.push { commit, hash := current, hasher := hasher.name }
          | none => existing.snapshots.push { commit, hash := current, hasher := hasher.name }
        let note := if opts.note.isEmpty then existing.note else opts.note
        let entry : ProtectedMark := { name, note, snapshots }
        let marks := { marks with
          protectedDecls := upsert marks.protectedDecls (·.name) name entry }
        marks.save opts.marksPath
        IO.eprintln s!"trust: {name} protected at {commit} ({hasher.name} {current})"
        return 0
  | "characterize" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, positionals) =>
      if positionals.size < 2 then
        IO.eprintln "error: expected <module> <definition> [<theorem>...]"
        return 1
      let moduleString := positionals[0]!
      let (env, defName) ← loadAndResolve moduleString positionals[1]!
      let definition := s!"{privateToUserName defName}"
      let marks ← Marks.load opts.marksPath
      if opts.remove then
        let marks := { marks with
          characterizations := marks.characterizations.filter fun c => c.definition != definition }
        marks.save opts.marksPath
        IO.eprintln s!"trust: {definition} is no longer characterized"
        return 0
      if positionals.size < 3 then
        IO.eprintln "error: expected at least one characterising theorem"
        return 1
      -- Every theorem is resolved before anything is written, so a typo cannot
      -- leave a half-written characterization behind.
      let mut theorems := #[]
      for i in [2:positionals.size] do
        let thmName ← exceptToIO <|
          AFTK.resolveDeclaration env moduleString.toName positionals[i]!.toName
        theorems := theorems.push s!"{privateToUserName thmName}"
      let entry : Characterization := { definition, theorems, note := opts.note }
      let marks := { marks with
        characterizations := upsert marks.characterizations (·.definition) definition entry }
      marks.save opts.marksPath
      IO.eprintln s!"trust: {definition} characterized by {String.intercalate ", " theorems.toList}"
      return 0
  | "check" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, positionals) =>
      if positionals.size != 1 then
        IO.eprintln "error: expected <module>"
        return 1
      let env ← AFTK.loadModuleEnvironment positionals[0]!.toName
      let marks ← Marks.load opts.marksPath
      let results ← checkAllProtected env defaultHasher marks
      for (name, status) in results do
        IO.println (status.describe name)
      let warnings := results.filter fun (_, status) => status.isWarning
      if warnings.isEmpty then
        IO.eprintln s!"trust: {results.size} protected declarations, all unchanged"
        return 0
      else
        IO.eprintln s!"trust: {warnings.size} of {results.size} protected declarations need attention"
        return 1
  | "sync-marks" :: rest =>
    match parseExport rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (config, moduleString) =>
      let dir := config.outDir / config.repo
      if !(← dir.pathExists) then
        IO.eprintln s!"error: no index at {dir}"
        return 1
      let env ← AFTK.loadModuleEnvironment moduleString.toName
      if ← writeMarks env dir config.marksPath then
        IO.eprintln s!"trust: refreshed {dir}/marks.json"
      else
        IO.eprintln s!"trust: {config.marksPath} has no marks; nothing written"
      return 0
  | "marks" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, _) =>
      let marks ← Marks.load opts.marksPath
      IO.println (toJson marks).pretty
      return 0
  | "conformance" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, _) =>
      let dir : System.FilePath := if opts.out.isEmpty then "conformance" else opts.out
      if opts.check then
        let problems ← Conformance.check dir
        for problem in problems do IO.eprintln s!"conformance: {problem}"
        if problems.any (!·.startsWith "SKIPPED") then return 1 else
          IO.println s!"conformance: {dir} agrees with this implementation"
          return 0
      else
        Conformance.write dir
        IO.println s!"conformance: wrote vectors to {dir}"
        return 0
  | "serve-marks" :: rest =>
    match parseMark rest with
    | .error msg =>
      IO.eprintln s!"error: {msg}"
      return 1
    | .ok (opts, positionals) =>
      -- With a module, protecting a declaration from the browser records its
      -- hash immediately; without one, the endpoint still serves and writes,
      -- and a newly protected declaration waits for `trust protect` as it did
      -- when a Vite middleware owned this file.
      let hashOf ←
        if h : 0 < positionals.size then do
          let moduleName := positionals[0].toName
          let env ← AFTK.loadModuleEnvironment moduleName
          let hasher := defaultHasher
          pure fun (name : String) => do
            match ← hasher.hash env name.toName with
            | some hash => pure (some (hash, hasher.name))
            | none => pure none
        else do
          IO.eprintln "trust: no module given, so new protections record no hash"
          pure fun _ => pure none
      serveMarks opts.marksPath (UInt16.ofNat opts.port) hashOf
      return 0
  | "cert" :: rest =>
    -- The certificate workflow moved to chrisflav/trust-cli.  It is a separate
    -- tool because it is for a person's keys and network rather than for a
    -- library's CI, and keeping a half-working copy here would only mean two
    -- implementations of the same commands to keep honest.  The stub stays
    -- until the next toolchain bump, since a release here is a release for a
    -- Lean and "one release" is the wrong unit.
    let sub := rest.headD ""
    IO.eprintln s!"error: `trust cert {sub}` moved to `trust-cert {sub}`."
    IO.eprintln "  https://github.com/chrisflav/trust-cli"
    IO.eprintln ""
    IO.eprintln "Certificates are issued, signed, published and checked there; this"
    IO.eprintln "binary is the exporter, and keeps the commands that read a Lean"
    IO.eprintln "environment.  Both apply the same rules -- `Trust.Federation` is in"
    IO.eprintln "this library and `trust-cert` calls it."
    return 1
  | cmd :: _ =>
    IO.eprintln s!"error: unknown command `{cmd}`\n\n{helpText}"
    return 1

end Trust