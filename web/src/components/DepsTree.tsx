import { memo, useEffect, useRef, useState } from 'react'
import type { GraphSource } from '../data/source'
import type { EdgeKind, NodeId } from '../data/types'
import { KindBadge } from './KindBadge'

export type Direction = 'dependencies' | 'dependents'

/**
 * Children revealed at a time.
 *
 * Common declarations have enormous fan-in — `Nat` has 32,967 dependents — and
 * rendering a row per dependent locks up the browser.  Rows are revealed in
 * pages instead.
 */
const PAGE = 50

interface TreeProps {
  source: GraphSource
  id: NodeId
  direction: Direction
  onSelect: (id: NodeId) => void
  depth?: number
  /** How this node was reached from its parent; absent at the root. */
  via?: EdgeKind
  /**
   * Row to highlight, and the route to it.
   *
   * A node picked in the graph has to be findable here, which means opening
   * every row between the root and it — and paging far enough into each of
   * those rows to reach the child that continues the path.
   */
  selected?: NodeId | null
  revealPath?: NodeId[] | null
  /** Marked trusted, and so a leaf while "up to trusted" is on. */
  isTrusted?: (id: NodeId) => boolean
  /** Dependencies stand in for this declaration's own, while the mode is on. */
  isCharacterized?: (id: NodeId) => boolean
  /**
   * Whether some declaration above this row was trusted.
   *
   * What a trusted declaration rests on is already covered by the judgement, so
   * it recedes; the trusted row itself does not.
   */
  beneathTrusted?: boolean
}

/**
 * A lazily expanding dependency tree.
 *
 * `DESIGN.md` asks to show the direct definitional dependencies of a statement
 * and to descend into a dependency when it is clicked, so children are fetched
 * only when a row is opened — a collapsed row costs one `degree` lookup, not a
 * neighbour list.  The same DAG node reached along two paths is rendered twice
 * here, which is intentional: this is the tree view, and the graph view is
 * where sharing is made visible.
 */
export const DepsTree = memo(function DepsTree({
  source,
  id,
  direction,
  onSelect,
  depth = 0,
  via,
  selected,
  revealPath,
  isTrusted,
  isCharacterized,
  beneathTrusted = false,
}: TreeProps) {
  const [open, setOpen] = useState(depth === 0)
  const [shown, setShown] = useState(PAGE)
  const row = useRef<HTMLDivElement | null>(null)
  const decl = source.node(id)

  // The next row along the route to the highlighted node, if this row is on it.
  const onPath = revealPath != null && revealPath[depth] === id
  const nextOnPath = onPath ? revealPath[depth + 1] : undefined
  const isSelected = selected === id

  // Bring a revealed row into view once, when it becomes the selected one.
  useEffect(() => {
    if (isSelected && row.current) {
      row.current.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [isSelected])

  if (!decl) return null

  // Cheap: reads adjacency offsets rather than building the neighbour list.
  const childCount = source.degree(id, direction)

  // Only an open row pays for its children, and it fetches only the rows it is
  // about to draw.  Filtering — by repository, or by what the reader has hidden
  // — is already applied by the source it was given, so a filtered row costs
  // what it displays rather than what it could have displayed.

  // A row on the route to the highlighted node opens itself, and pages far
  // enough in to reach the child that carries the route on.  Without the second
  // part a node lying past the first fifty children would be revealed into a
  // list that does not contain it.
  let reach = shown
  if (nextOnPath !== undefined) {
    let index = 0
    let at = -1
    source.forEachChild(id, direction, (target) => {
      if (target === nextOnPath) {
        at = index
        return false
      }
      index++
      return true
    })
    if (at >= 0) reach = Math.max(shown, at + 1)
  }
  const isOpen = open || nextOnPath !== undefined

  // One row beyond what we draw, so that "is there more?" is answered by the
  // walk itself rather than by comparing against `childCount`, which only ever
  // was an upper bound.
  const fetched = isOpen ? source.childEdges(id, direction, reach + 1) : []
  const hasMore = fetched.length > reach
  const visible = hasMore ? fetched.slice(0, reach) : fetched

  // `childCount` counts what the filter would reject too, and a dependency named
  // in both the statement and the body counts twice there but is listed once, so
  // it is only shown while the row still has rows we have not drawn.
  const shownCount = isOpen && !hasMore ? visible.length : childCount
  const trusted = isTrusted?.(id) ?? false
  const characterized = isCharacterized?.(id) ?? false

  return (
    <div className="tree-node" style={{ marginLeft: depth === 0 ? 0 : 16 }}>
      <div
        className={`tree-row${isSelected ? ' selected' : ''}${beneathTrusted ? ' beneath-trusted' : ''}`}
        ref={row}
      >
        <button
          className="twisty"
          disabled={childCount === 0}
          onClick={() => setOpen(!isOpen)}
          aria-label={isOpen ? 'collapse' : 'expand'}
        >
          {childCount === 0 ? '·' : isOpen ? '▾' : '▸'}
        </button>
        <KindBadge decl={decl} />
        <button className="decl-name" onClick={() => onSelect(id)} title={decl.module}>
          {decl.name}
        </button>
        {via === 'body' && (
          <span className="via" title="reached by unfolding the parent's definition">
            body
          </span>
        )}
        {trusted && (
          <span
            className="via trusted"
            title="Marked trusted.  In “up to trusted” mode its own dependencies are not traced."
          >
            trusted
          </span>
        )}
        {characterized && (
          <span className="via characterized" title="Shown as its characterising theorems.">
            characterized
          </span>
        )}
        {shownCount > 0 && <span className="count">{shownCount}</span>}
      </div>
      {isOpen && (
        <>
          {visible.map((child) => (
            <DepsTree
              key={`${child.id}-${child.kind}`}
              source={source}
              id={child.id}
              direction={direction}
              onSelect={onSelect}
              depth={depth + 1}
              via={child.kind}
              selected={selected}
              revealPath={revealPath}
              isTrusted={isTrusted}
              isCharacterized={isCharacterized}
              beneathTrusted={beneathTrusted || trusted}
            />
          ))}
          {hasMore && (
            <button className="show-more" onClick={() => setShown(reach + PAGE)}>
              show more — {visible.length} shown
            </button>
          )}
        </>
      )}
    </div>
  )
})