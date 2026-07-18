import type { Accept, GraphSource } from './source'
import type { MarksIndex } from './marks'
import type { Decl, DeclCode, EdgeKind, IndexMeta, NodeId } from './types'

/**
 * The index as it looks when you only trace dependencies down to what you
 * already trust.
 *
 * Two rules from `DESIGN.md`, both applied to the dependency direction only —
 * asking who depends on a declaration is a question about the library, not
 * about what you have accepted:
 *
 * * a **trusted** declaration is a leaf.  You vouched for it, so what it rests
 *   on is no longer part of what you have to take on faith.  It stays visible
 *   and marked, and focusing it shows its dependencies again, which is why the
 *   root is exempt: cutting the tree at the declaration being looked at would
 *   leave nothing to look at.
 *
 * * a **characterized** definition has its dependencies replaced by the
 *   theorems that characterize it.  What you have to trust about `Finset` is
 *   not that it is a `Multiset` with a proof attached, but that it behaves the
 *   way its characterising theorems say.  The tree then continues through those
 *   theorems' own dependencies, which is what makes this a re-rooting of the
 *   question rather than a truncation of it.
 *
 * Characterization is applied at the root too: replacing a declaration's
 * dependencies is the whole point of looking at it in this mode.
 */
export function trustedCutSource(
  base: GraphSource,
  marks: MarksIndex,
  root: NodeId | null,
): GraphSource {
  const trusted = new Set<NodeId>()
  for (const mark of marks.marks.trusted) {
    const id = base.findByName(mark.name)
    if (id !== null) trusted.add(id)
  }

  // Names are resolved once, here, rather than per traversal step: a closure
  // walk asks for a node's children thousands of times.
  const replacement = new Map<NodeId, NodeId[]>()
  for (const characterization of marks.marks.characterizations) {
    const id = base.findByName(characterization.definition)
    if (id === null) continue
    const theorems: NodeId[] = []
    for (const name of characterization.theorems) {
      const target = base.findByName(name)
      // A theorem the index does not contain is skipped rather than faked; the
      // marks file may name declarations from a repository this index omits.
      if (target !== null && target !== id) theorems.push(target)
    }
    if (theorems.length > 0) replacement.set(id, theorems)
  }

  const forEachChild = (
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    visit: (target: NodeId, kind: EdgeKind) => boolean,
  ): void => {
    if (direction === 'dependents') {
      base.forEachChild(id, direction, visit)
      return
    }
    const theorems = replacement.get(id)
    if (theorems) {
      for (const target of theorems) if (!visit(target, 'statement')) return
      return
    }
    if (id !== root && trusted.has(id)) return
    base.forEachChild(id, direction, visit)
  }

  const childEdges = (
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    limit = Infinity,
    accept?: Accept,
  ): { id: NodeId; kind: EdgeKind }[] => {
    const out: { id: NodeId; kind: EdgeKind }[] = []
    if (limit <= 0) return out
    forEachChild(id, direction, (target, kind) => {
      if (accept && !accept(target)) return true
      out.push({ id: target, kind })
      return out.length < limit
    })
    return out
  }

  return {
    meta: (): IndexMeta => base.meta(),
    node: (id: NodeId): Decl => base.node(id),
    forEachChild,
    childEdges,
    dependencyEdges: (id, limit, accept) => childEdges(id, 'dependencies', limit, accept),
    dependencies: (id) => childEdges(id, 'dependencies').map((edge) => edge.id),
    dependents: (id) => base.dependents(id),
    degree: (id, direction) => {
      if (direction === 'dependents') return base.degree(id, direction)
      let count = 0
      forEachChild(id, 'dependencies', () => {
        count++
        return true
      })
      return count
    },
    search: (query, limit) => base.search(query, limit),
    findByName: (name) => base.findByName(name),
    code: (id): Promise<DeclCode | null> => base.code(id),
    repos: () => base.repos(),
    repoOf: (id) => base.repoOf(id),
  }
}

/**
 * A path from `root` down to `target`, or null when there is none within reach.
 *
 * Used to open the tree at a node that was picked in the graph.  Breadth-first,
 * so the path found is the shortest one, which is the one with the fewest rows
 * to expand.  Bounded because a declaration can have hundreds of thousands of
 * dependents and the answer is only worth having if it arrives immediately.
 */
export function pathTo(
  source: GraphSource,
  root: NodeId,
  target: NodeId,
  direction: 'dependencies' | 'dependents',
  maxDepth = 12,
  maxNodes = 20000,
): NodeId[] | null {
  if (root === target) return [root]
  const parent = new Map<NodeId, NodeId>([[root, root]])
  let frontier: NodeId[] = [root]
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: NodeId[] = []
    for (const id of frontier) {
      let found = false
      source.forEachChild(id, direction, (child) => {
        if (parent.has(child)) return true
        parent.set(child, id)
        if (child === target) {
          found = true
          return false
        }
        next.push(child)
        return parent.size < maxNodes
      })
      if (found) {
        const path = [target]
        let step = id
        while (step !== root) {
          path.push(step)
          step = parent.get(step)!
        }
        path.push(root)
        return path.reverse()
      }
      if (parent.size >= maxNodes) return null
    }
    frontier = next
  }
  return null
}
