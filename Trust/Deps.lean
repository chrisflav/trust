import Lean
import AFTK
import Trust.Graph

/-!
# Definitional dependencies

`aftk` answers "which declarations does `d` transitively use", as a flat set,
traversing types and values together.  Trust needs something different:

* the *edges*, not just the reachable set, so the frontend can render a tree;
* dependencies of the **statement**, i.e. of the declaration's type only;
* a notion of **data-carrying**, so that traversal stops at proofs.

A constant is data-carrying when it is not itself a proof, i.e. when its type is
not a `Prop`.  The definitional closure descends through a node's type *and*
value when the node is data-carrying, and treats propositional nodes as leaves:
a theorem appears in the graph, but we do not walk into its proof term.

Note that a `Prop`-valued *definition* such as `def IsEven (n : Nat) : Prop` has
type `Nat → Prop`, which is not itself a `Prop`, so it counts as data-carrying
and we do unfold it.  Only actual proofs terminate the traversal.
-/

namespace Trust

open Lean

/-- Run a `MetaM` action against an already-imported environment. -/
def runMetaM (env : Environment) (x : MetaM α) : IO α := do
  let ctx : Core.Context :=
    { fileName := "<trust>", fileMap := default, maxHeartbeats := 0, maxRecDepth := 8000 }
  let ((a, _), _) ← (x.run {} {}).toIO ctx { env := env }
  return a

/-- Constants occurring in the type of `declName`, i.e. in its statement. -/
def statementConstants (env : Environment) (declName : Name) : Array Name :=
  match env.find? declName with
  | none => #[]
  | some info => info.type.getUsedConstants.filter fun n => (env.find? n).isSome

/--
Constants occurring in the types of an inductive type's constructors.

An inductive type has no value, so `value?` reports nothing for it.  Taken at
face value that makes every structure a leaf: `Finset` would carry no
dependencies at all, when what it *is* — a `Multiset` together with a proof that
it has no duplicates — lives entirely in the type of its constructor.  So the
constructors' types stand in for a body here.

The type itself and its own constructors are dropped: every constructor mentions
the type it constructs, and an edge from a declaration to itself says nothing.
The constructors remain reachable from the rendered body, where they are shown.
-/
def constructorConstants (env : Environment) (val : InductiveVal) : Array Name :=
  let internal := val.ctors.foldl (fun s c => s.insert c) (({} : NameHashSet).insert val.name)
  val.ctors.foldl (init := #[]) fun out ctor =>
    match env.find? ctor with
    | none => out
    | some info =>
      out ++ info.type.getUsedConstants.filter fun n =>
        (env.find? n).isSome && !internal.contains n

/-- Constants occurring in the value of `declName`, i.e. in its body. -/
def bodyConstants (env : Environment) (declName : Name) : Array Name :=
  match env.find? declName with
  | none => #[]
  | some (.inductInfo val) => constructorConstants env val
  | some info =>
    match info.value? (allowOpaque := true) with
    | none => #[]
    | some value => value.getUsedConstants.filter fun n => (env.find? n).isSome

/--
Cache for the `Prop`-ness of declarations.

Deciding whether a declaration is a proof needs `Meta.isProp`, which is far too
slow to run once per edge, so results are memoised.  Theorems are answered
without entering `MetaM` at all, which covers the large majority of declarations
in a library like Mathlib.
-/
structure PropCache where
  /-- Memoised results of `isProof`. -/
  cache : Std.HashMap Name Bool := {}
  deriving Inhabited

/-- Whether `declName` is a proof, i.e. its type is a `Prop`. -/
def isProof (env : Environment) (declName : Name) : StateRefT PropCache IO Bool := do
  if let some result := (← get).cache[declName]? then
    return result
  let result ←
    match env.find? declName with
    | none => pure false
    | some info =>
      -- A theorem is a proof by construction; no need to elaborate anything.
      if info.isTheorem then
        pure true
      else
        runMetaM env (Meta.isProp info.type)
  modify fun s => { s with cache := s.cache.insert declName result }
  return result

/--
Successors of `declName` that are fit to display, contracting through internal
declarations.

`aftk` traverses internal declarations but omits them from output; doing the
same naively would break the edge structure, so instead we splice: when a
successor is an internal detail, its own successors take its place.
-/
partial def displayableSuccessors
    (env : Environment) (successors : Name → Array Name) (declName : Name) : Array Name :=
  let rec go (todo : List Name) (seen : NameHashSet) (out : Array Name) : Array Name :=
    match todo with
    | [] => out
    | n :: rest =>
      if seen.contains n then
        go rest seen out
      else
        let seen := seen.insert n
        if AFTK.shouldDisplay env n then
          go rest seen (out.push n)
        else
          go ((successors n).toList ++ rest) seen out
  go (successors declName).toList (({} : NameHashSet).insert declName) #[]

/-- Intern a declaration as a graph node, computing its kind and `Prop`-ness. -/
def intern (env : Environment) (b : GraphBuilder) (declName : Name) :
    StateRefT PropCache IO (GraphBuilder × Nat) := do
  if let some id := b.id? declName then
    return (b, id)
  let id := b.nodes.size
  let isProp ← isProof env declName
  let kind :=
    match env.find? declName with
    | some info => DeclKind.ofConstantInfo info
    | none => .ax
  let node : Node :=
    { id
      name := s!"{privateToUserName declName}"
      module := s!"{AFTK.moduleOfD env declName}"
      kind
      isProp
      isData := !isProp }
  return ({ b with ids := b.ids.insert declName id, nodes := b.nodes.push node }, id)

/-- Axioms `declName` depends on, and whether `sorryAx` is among them. -/
def axiomsOf (env : Environment) (declName : Name) : IO (Array String × Bool) := do
  let axioms ← runMetaM env (collectAxioms declName)
  let names := axioms.map fun n => s!"{n}"
  return (names, axioms.any fun n => n == ``sorryAx)

/--
The definitional closure of a declaration's statement.

Starts from the constants in `root`'s type, then repeatedly expands
data-carrying nodes through their types and values.  Propositional nodes are
recorded but not expanded.  `maxDepth` bounds the expansion; `none` means
expand until closed.
-/
def definitionalClosure (env : Environment) (root : Name) (maxDepth : Option Nat := none) :
    IO Graph := do
  let go : StateRefT PropCache IO Graph := do
    let (b, rootId) ← intern env {} root
    let mut b := b
    -- Queue entries pair a declaration with the depth at which it was reached.
    let mut todo : List (Name × Nat) := []
    let mut expanded : NameHashSet := ({} : NameHashSet).insert root
    -- The root is expanded like any other node: always through its statement, and
    -- through its body as well when it carries data.  A theorem root therefore
    -- contributes its statement but never its proof term.
    let rootIsProof ← isProof env root
    let rootSuccessors :=
      if rootIsProof then
        [(statementConstants env, EdgeKind.statement)]
      else
        [(statementConstants env, EdgeKind.statement), (bodyConstants env, EdgeKind.body)]
    for (successors, kind) in rootSuccessors do
      for dep in displayableSuccessors env successors root do
        let (b', depId) ← intern env b dep
        b := b'.addEdge rootId depId kind
        todo := (dep, 1) :: todo
    repeat
      match todo with
      | [] => break
      | (declName, depth) :: rest =>
        todo := rest
        if expanded.contains declName then
          continue
        expanded := expanded.insert declName
        if let some maxDepth := maxDepth then
          if depth > maxDepth then
            continue
        -- Proofs are leaves: they appear in the graph, but we never walk into them.
        if ← isProof env declName then
          continue
        let some srcId := b.id? declName | continue
        for (successors, kind) in
            [(statementConstants env, EdgeKind.statement), (bodyConstants env, EdgeKind.body)] do
          for dep in displayableSuccessors env successors declName do
            let (b', depId) ← intern env b dep
            b := b'.addEdge srcId depId kind
            todo := (dep, depth + 1) :: todo
    return b.build rootId
  let (graph, _) ← go.run {}
  return graph

/-- Attach axiom information to the root node of a graph. -/
def withRootAxioms (env : Environment) (root : Name) (graph : Graph) : IO Graph := do
  let (axioms, usesSorry) ← axiomsOf env root
  if h : graph.root < graph.nodes.size then
    let rootNode := graph.nodes[graph.root]
    return { graph with
      nodes := graph.nodes.set graph.root { rootNode with axioms, usesSorry } }
  else
    return graph

end Trust