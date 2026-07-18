import Lean
import AFTK
import Trust.Graph
import Trust.Deps

/-!
# Forward dependencies

"Who depends on this declaration" is exactly what `aftk`'s `rdeps` computes, so
this module is a thin layer over `AFTK.reverseDependencyMap` and friends rather
than a reimplementation.  We only reshape the answer into a `Graph`, and default
to *direct* dependents because that is what the UI navigates one step at a time.

Unlike the definitional closure, dependents are computed over types *and*
values: a theorem that uses a declaration only in its proof genuinely depends on
it, and `DESIGN.md` asks for forward dependencies including theorems.
-/

namespace Trust

open Lean

/-- Dependents of `root`, as a graph with edges pointing from dependent to `root`. -/
def dependentsGraph (env : Environment) (root : Name) (filter : AFTK.ModuleFilter)
    (transitive : Bool := false) : IO Graph := do
  let reverse := AFTK.reverseDependencyMap env (AFTK.relevantModulesForOutput env root filter)
  let reachable :=
    if transitive then
      AFTK.reachableFrom root (AFTK.directDependents reverse)
    else
      AFTK.directDependents reverse root
  let displayable := AFTK.displayableReachable env root filter reachable
  let go : StateRefT PropCache IO Graph := do
    let (b, rootId) ← intern env {} root
    let mut b := b
    for declName in displayable do
      let (b', id) ← intern env b declName
      -- The edge points the way the dependency runs: dependent → dependency.
      b := b'.addEdge id rootId .statement
    return b.build rootId
  let (graph, _) ← go.run {}
  return graph

end Trust