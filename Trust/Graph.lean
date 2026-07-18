import Lean

/-!
# Wire types for trust dependency graphs

These are the types that cross the Lean/TypeScript boundary.  They are kept
deliberately flat: nodes carry integer ids and edges refer to those ids, so that
the exported edge files stay compact for repositories the size of Mathlib.
-/

namespace Trust

open Lean

/-- The kind of a declaration, mirroring `Lean.ConstantInfo`. -/
inductive DeclKind where
  /-- An axiom. -/
  | ax
  /-- A definition. -/
  | defn
  /-- A theorem. -/
  | thm
  /-- An opaque constant. -/
  | opaq
  /-- A quotient primitive. -/
  | quot
  /-- An inductive type. -/
  | indt
  /-- A constructor of an inductive type. -/
  | ctor
  /-- An automatically generated recursor. -/
  | recr
  deriving Inhabited, BEq, Repr

namespace DeclKind

/-- The wire representation of a declaration kind. -/
def toString : DeclKind → String
  | .ax => "axiom"
  | .defn => "def"
  | .thm => "theorem"
  | .opaq => "opaque"
  | .quot => "quot"
  | .indt => "inductive"
  | .ctor => "ctor"
  | .recr => "recursor"

/-- Parse the wire representation of a declaration kind. -/
def ofString? : String → Option DeclKind
  | "axiom" => some .ax
  | "def" => some .defn
  | "theorem" => some .thm
  | "opaque" => some .opaq
  | "quot" => some .quot
  | "inductive" => some .indt
  | "ctor" => some .ctor
  | "recursor" => some .recr
  | _ => none

/-- The kind of a declaration, read off its `ConstantInfo`. -/
def ofConstantInfo : ConstantInfo → DeclKind
  | .axiomInfo _ => .ax
  | .defnInfo _ => .defn
  | .thmInfo _ => .thm
  | .opaqueInfo _ => .opaq
  | .quotInfo _ => .quot
  | .inductInfo _ => .indt
  | .ctorInfo _ => .ctor
  | .recInfo _ => .recr

end DeclKind

instance : ToJson DeclKind := ⟨fun k => Json.str k.toString⟩

instance : FromJson DeclKind where
  fromJson? j := do
    let s ← j.getStr?
    match DeclKind.ofString? s with
    | some k => return k
    | none => throw s!"unknown declaration kind `{s}`"

/-- A node in a dependency graph: one Lean declaration. -/
structure Node where
  /-- Index of this node in the enclosing node table. -/
  id : Nat
  /-- User-facing declaration name, e.g. `Nat.gcd`. -/
  name : String
  /-- Module the declaration lives in, e.g. `Mathlib.Data.Nat.Defs`. -/
  module : String
  /-- Declaration kind. -/
  kind : DeclKind
  /-- Whether the declaration is a proof, i.e. its type is a `Prop`. -/
  isProp : Bool
  /-- Whether the declaration carries data, i.e. it is not a proof. -/
  isData : Bool
  /-- Axioms the declaration depends on.  Only populated for query roots. -/
  axioms : Array String := #[]
  /-- Whether the declaration transitively depends on `sorryAx`. -/
  usesSorry : Bool := false
  deriving Inhabited, ToJson, FromJson

/-- Where an edge came from: the type of a declaration, or its value. -/
inductive EdgeKind where
  /-- The target occurs in the source's type, i.e. in its statement. -/
  | statement
  /-- The target occurs in the source's value, i.e. in its body. -/
  | body
  deriving Inhabited, BEq, Repr

namespace EdgeKind

/-- The wire representation of an edge kind. -/
def toString : EdgeKind → String
  | .statement => "statement"
  | .body => "body"

/-- Parse the wire representation of an edge kind. -/
def ofString? : String → Option EdgeKind
  | "statement" => some .statement
  | "body" => some .body
  | _ => none

end EdgeKind

instance : ToJson EdgeKind := ⟨fun k => Json.str k.toString⟩

instance : FromJson EdgeKind where
  fromJson? j := do
    let s ← j.getStr?
    match EdgeKind.ofString? s with
    | some k => return k
    | none => throw s!"unknown edge kind `{s}`"

/-- A directed edge: `src` depends on `tgt`. -/
structure Edge where
  /-- Node id of the depending declaration. -/
  src : Nat
  /-- Node id of the declaration depended upon. -/
  tgt : Nat
  /-- Whether the dependency arises from the source's type or its value. -/
  kind : EdgeKind
  deriving Inhabited, BEq, ToJson, FromJson

/-- A dependency graph rooted at a single declaration. -/
structure Graph where
  /-- Node id of the declaration the query was about. -/
  root : Nat
  /-- All nodes, indexed by their `id`. -/
  nodes : Array Node
  /-- All edges between nodes. -/
  edges : Array Edge
  deriving Inhabited, ToJson, FromJson

/--
Accumulator for graph construction.

`ids` interns declaration names so that a declaration reached along several paths
becomes one node.
-/
structure GraphBuilder where
  /-- Interning table from declaration name to node id. -/
  ids : Std.HashMap Name Nat := {}
  /-- Nodes accumulated so far, in id order. -/
  nodes : Array Node := #[]
  /-- Edges accumulated so far. -/
  edges : Array Edge := #[]
  deriving Inhabited

namespace GraphBuilder

/-- Look up the node id of an already-interned declaration. -/
def id? (b : GraphBuilder) (declName : Name) : Option Nat :=
  b.ids[declName]?

/-- Record an edge.  Callers are responsible for having interned both endpoints. -/
def addEdge (b : GraphBuilder) (src tgt : Nat) (kind : EdgeKind) : GraphBuilder :=
  { b with edges := b.edges.push { src, tgt, kind } }

/-- Finish construction, rooted at `root`. -/
def build (b : GraphBuilder) (root : Nat) : Graph :=
  { root, nodes := b.nodes, edges := b.edges }

end GraphBuilder

end Trust