import { memo, useCallback, useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react'
import type { ClosureSize, GraphSource } from '../data/source'
import { beginClosureSize, closure, filterSource, type Accept } from '../data/source'
import { NodePreview } from './NodePreview'
import { GraphLegend } from './GraphLegend'
import type { Graph, NodeId } from '../data/types'
import type { Direction } from './DepsTree'

const NODE_HEIGHT = 26
const PADDING = 24

/**
 * How the graph is drawn.
 *
 * The pane and the expanded view differ only in these, so both go through the
 * same layout and the same geometry; the expanded view is not a second
 * renderer, it is the same one with room to breathe.
 */
export interface GraphOptions {
  /** Traversal budgets: how much of the closure is drawn at all. */
  maxNodes: number
  maxEdges: number
  nodeWidth: number
  layerGap: number
  nodeGap: number
  /** Widest a layer may get before wrapping; null lets a layer run as wide as it likes. */
  canvasWidth: number | null
  labels: 'full' | 'short' | 'truncated'
  /**
   * Which way the layers run.
   *
   * Vertical puts the root at the top and dependencies below it.  Horizontal
   * turns that a quarter turn: layers become columns running left to right,
   * which suits a graph that is deep and narrow — and screens are wider than
   * they are tall, so a long chain fits far better on its side.
   */
  orientation: 'vertical' | 'horizontal'
  showStatement: boolean
  showBody: boolean
  /** Mute what sits below a trusted declaration. */
  dimBeneathTrusted: boolean
}

/** What the side pane uses: a few hundred elements, scaled to fit its column. */
export const PANE_OPTIONS: GraphOptions = {
  maxNodes: 150,
  maxEdges: 400,
  nodeWidth: 150,
  layerGap: 74,
  nodeGap: 14,
  canvasWidth: 980,
  labels: 'truncated',
  orientation: 'vertical',
  showStatement: true,
  showBody: true,
  dimBeneathTrusted: true,
}

/**
 * What the expanded view starts from: more of the graph, no width cap, and on
 * its side.
 *
 * Horizontal reads better for the long chains a dependency closure usually is,
 * and it puts the layer order along the axis a screen has most room in.  It is
 * not uniformly better: a closure with a few very wide layers — one definition
 * pulling in a family of instances — stacks those down the page and fits *less*
 * on screen than the vertical layout does.  Hence the toggle.
 *
 * The side pane stays vertical, where the column it sits in is the narrow
 * dimension and wrapping wide layers is the only thing that fits.
 */
export const EXPANDED_OPTIONS: GraphOptions = {
  ...PANE_OPTIONS,
  maxNodes: 400,
  maxEdges: 1200,
  canvasWidth: null,
  orientation: 'horizontal',
}

interface Placed {
  id: NodeId
  x: number
  y: number
  layer: number
}

/**
 * Assign each node to a layer and order nodes within layers.
 *
 * This is a cut-down Sugiyama: longest-path layering (so an edge always points
 * down a layer), then a couple of barycenter passes to reduce crossings by
 * pulling each node towards the average position of its predecessors.  It is
 * enough for the few-hundred-node closures we render and avoids taking on a
 * graph-layout dependency.
 */
function layout(
  graph: Graph,
  options: GraphOptions,
): { placed: Placed[]; width: number; height: number } {
  const layerOf = new Map<NodeId, number>()
  const successors = new Map<NodeId, NodeId[]>()
  for (const edge of graph.edges) {
    const list = successors.get(edge.src) ?? []
    list.push(edge.tgt)
    successors.set(edge.src, list)
  }

  // Longest-path layering from the root.  Relaxation converges in as many
  // rounds as the longest path is long, which the closure depth already bounds,
  // so the guard is a small constant rather than the node count — the latter
  // made this quadratic in the graph size.
  layerOf.set(graph.root, 0)
  let changed = true
  let guard = 0
  while (changed && guard++ < 64) {
    changed = false
    for (const edge of graph.edges) {
      const from = layerOf.get(edge.src)
      if (from === undefined) continue
      const to = layerOf.get(edge.tgt)
      if (to === undefined || to < from + 1) {
        layerOf.set(edge.tgt, from + 1)
        changed = true
      }
    }
  }
  // Anything unreachable through the kept edges goes in a trailing layer.
  const maxLayer = Math.max(0, ...layerOf.values())
  for (const node of graph.nodes) {
    if (!layerOf.has(node.id)) layerOf.set(node.id, maxLayer + 1)
  }

  const layers: NodeId[][] = []
  for (const node of graph.nodes) {
    const layer = layerOf.get(node.id)!
    ;(layers[layer] ??= []).push(node.id)
  }

  const predecessors = new Map<NodeId, NodeId[]>()
  for (const edge of graph.edges) {
    const list = predecessors.get(edge.tgt) ?? []
    list.push(edge.src)
    predecessors.set(edge.tgt, list)
  }

  const positionIn = new Map<NodeId, number>()
  for (const layer of layers) {
    layer?.forEach((id, i) => positionIn.set(id, i))
  }
  for (let pass = 0; pass < 3; pass++) {
    for (let l = 1; l < layers.length; l++) {
      const layer = layers[l]
      if (!layer) continue
      const barycenter = new Map<NodeId, number>()
      for (const id of layer) {
        const preds = predecessors.get(id) ?? []
        const values = preds.map((p) => positionIn.get(p)).filter((v): v is number => v !== undefined)
        barycenter.set(id, values.length ? values.reduce((a, b) => a + b, 0) / values.length : positionIn.get(id)!)
      }
      layer.sort((a, b) => barycenter.get(a)! - barycenter.get(b)!)
      layer.forEach((id, i) => positionIn.set(id, i))
    }
  }

  // A single layer can hold dozens of nodes — one definition often pulls in a
  // whole family of instances.  In a fixed-width canvas such a layer has to wrap
  // onto several rows, or the drawing becomes illegible once scaled to fit.
  // With no width cap the layer runs as wide as it needs and the canvas grows
  // sideways instead, which is the point of the expanded view.
  const { nodeWidth, nodeGap, layerGap, canvasWidth } = options
  const horizontal = options.orientation === 'horizontal'

  // One axis runs *along* a layer, the other *across* from one layer to the
  // next.  Rotating the drawing is only a matter of which is which; the gap
  // between layers is kept the same either way, which is why the across stride
  // is derived from `layerGap` rather than used as it stands.
  const alongStride = horizontal ? NODE_HEIGHT + nodeGap : nodeWidth + nodeGap
  const acrossGap = Math.max(8, layerGap - NODE_HEIGHT)
  const acrossStride = horizontal ? nodeWidth + acrossGap : layerGap

  // Wrapping is a vertical-mode answer to a layer wider than the canvas.  Laid
  // out on its side a layer runs down the page instead, which scrolls, so there
  // is nothing to wrap against.
  const perRow =
    horizontal || canvasWidth === null
      ? Number.POSITIVE_INFINITY
      : Math.max(1, Math.floor((canvasWidth - 2 * PADDING + nodeGap) / alongStride))

  const widestRun = layers.reduce(
    (most, layer) => Math.max(most, Math.min(layer?.length ?? 0, perRow) * alongStride - nodeGap),
    0,
  )
  const alongExtent = horizontal
    ? widestRun + 2 * PADDING
    : (canvasWidth ?? Math.max(widestRun + 2 * PADDING, 320))

  const placed: Placed[] = []
  let run = 0
  layers.forEach((layer, l) => {
    if (!layer) return
    for (let start = 0; start < layer.length; start += perRow) {
      const chunk = layer.slice(start, start + Math.min(perRow, layer.length))
      const runLength = chunk.length * alongStride - nodeGap
      const lead = (alongExtent - runLength) / 2
      chunk.forEach((id, i) => {
        const along = lead + i * alongStride
        const across = PADDING + run * acrossStride
        placed.push({ id, layer: l, x: horizontal ? across : along, y: horizontal ? along : across })
      })
      run++
      if (perRow === Number.POSITIVE_INFINITY) break
    }
  })

  const acrossExtent = PADDING * 2 + run * acrossStride
  return horizontal
    ? { placed, width: acrossExtent, height: Math.max(alongExtent, 120) }
    : { placed, width: alongExtent, height: acrossExtent }
}

/**
 * The node label, at the length the reader asked for.
 *
 * Lean names are long and mostly common prefix — `Nat.gcd_dvd_left` shares
 * `Nat.` with everything around it — so the last component alone is often the
 * only part that distinguishes one node from its neighbours.
 */
function labelFor(name: string, options: GraphOptions): string {
  if (options.labels === 'full') return name
  if (options.labels === 'short') {
    const parts = name.split('.')
    return parts[parts.length - 1] || name
  }
  // Truncated: as much as fits a node of this width, at roughly 6px a character.
  const room = Math.max(6, Math.floor(options.nodeWidth / 6.6))
  return name.length > room ? `${name.slice(0, room - 1)}…` : name
}

/**
 * Drop edge kinds the reader has turned off, and any node left unreachable.
 *
 * Hiding the edges alone would leave nodes floating with nothing to connect
 * them, which reads as a bug rather than as a filter; a node is only in the
 * drawing if there is still a path to it from the root.
 */
function restrictToKinds(graph: Graph, statement: boolean, body: boolean): Graph {
  if (statement && body) return graph
  const edges = graph.edges.filter((edge) =>
    edge.kind === 'body' ? body : statement,
  )
  const reachable = new Set<NodeId>([graph.root])
  const outgoing = new Map<NodeId, NodeId[]>()
  for (const edge of edges) {
    const list = outgoing.get(edge.src)
    if (list) list.push(edge.tgt)
    else outgoing.set(edge.src, [edge.tgt])
  }
  const queue = [graph.root]
  while (queue.length > 0) {
    for (const target of outgoing.get(queue.pop()!) ?? []) {
      if (!reachable.has(target)) {
        reachable.add(target)
        queue.push(target)
      }
    }
  }
  return {
    ...graph,
    nodes: graph.nodes.filter((node) => reachable.has(node.id)),
    edges: edges.filter((edge) => reachable.has(edge.src) && reachable.has(edge.tgt)),
  }
}

/**
 * One edge and one node, memoised.
 *
 * Selecting a node changes the appearance of at most a handful of elements, but
 * the graph holds hundreds; without memoising, every selection re-rendered all
 * of them and cost tens of milliseconds per click.
 */
const GraphEdge = memo(function GraphEdge({
  d,
  kind,
  highlight,
  dim,
  offPath,
}: {
  d: string
  kind: string
  highlight: boolean
  dim: boolean
  offPath: boolean
}) {
  // Arrowheads are drawn only on highlighted edges.  An SVG marker on every
  // curved path is disproportionately expensive to rasterise, and the layered
  // layout already reads unambiguously downwards.
  return (
    <path
      className={`edge ${kind} ${highlight ? 'highlight' : ''} ${dim ? 'beneath-trusted' : ''} ${
        offPath ? 'off-path' : ''
      }`}
      d={d}
      markerEnd={highlight ? 'url(#arrow)' : undefined}
    />
  )
})

const GraphNode = memo(function GraphNode({
  x,
  y,
  width,
  label,
  title,
  classes,
  onClick,
  onDoubleClick,
  onEnter,
  onLeave,
}: {
  x: number
  y: number
  width: number
  label: string
  title: string
  classes: string
  onClick: () => void
  onDoubleClick: () => void
  onEnter: (event: ReactMouseEvent) => void
  onLeave: () => void
}) {
  return (
    <g
      className={classes}
      aria-label={title}
      onClick={onClick}
      onDoubleClick={onDoubleClick}
      onMouseEnter={onEnter}
      onMouseMove={onEnter}
      onMouseLeave={onLeave}
    >
      <rect x={x} y={y} width={width} height={NODE_HEIGHT} rx={5} />
      <text x={x + width / 2} y={y + NODE_HEIGHT / 2 + 4}>
        {label}
      </text>
    </g>
  )
})

interface GraphViewProps {
  source: GraphSource
  root: NodeId
  direction: Direction
  depth: number
  selected: NodeId
  /** Highlight a node without moving the view. */
  onSelect: (id: NodeId) => void
  /** Make a node the new root; a double click, so a single one can inspect. */
  onFocus: (id: NodeId) => void
  /** Whether a declaration has been vouched for, so it can be drawn as settled. */
  isTrusted?: (id: NodeId) => boolean
  /**
   * Fade everything the selection is not joined to.
   *
   * Only once a node has actually been picked.  The selection starts on the
   * root, and dimming the graph the moment it appears would answer a question
   * nobody asked.
   */
  dimUnconnected?: boolean
  /** Restrict which declarations are drawn at all. */
  accept?: Accept
  /** Whether a declaration is on the reader's hidden list. */
  isHidden?: (id: NodeId) => boolean
  onHide?: (name: string) => void
  onUnhide?: (name: string) => void
  /** Report the counts, for a caller that shows them in its own bar. */
  onStats?: (stats: { total: ClosureSize | null; nodes: number; edges: number; truncated: boolean }) => void
  /** How to draw it; defaults to what the side pane wants. */
  options?: GraphOptions
  /**
   * Scale the drawing down to the width available.
   *
   * True in the pane, where the alternative is the root scrolling out of view.
   * False in the expanded view, where the canvas keeps its natural size and the
   * container scrolls.
   */
  fit?: boolean
}

/** The full definitional dependency graph, laid out as a DAG. */
export function GraphView({
  source,
  root,
  direction,
  depth,
  selected,
  onSelect,
  onFocus,
  isTrusted,
  dimUnconnected = false,
  accept,
  isHidden,
  onHide,
  onUnhide,
  onStats,
  options = PANE_OPTIONS,
  fit = true,
}: GraphViewProps) {
  const [hover, setHover] = useState<{ id: NodeId; x: number; y: number } | null>(null)
  // Closing on `mouseleave` alone made the card unusable: reaching for the
  // button in it means leaving the node, which closed it before the click
  // landed.  Leaving only schedules the close, and the card cancels it.
  const closeTimer = useRef<number | null>(null)
  const cancelClose = useCallback(() => {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current)
      closeTimer.current = null
    }
  }, [])
  const scheduleClose = useCallback(() => {
    cancelClose()
    closeTimer.current = window.setTimeout(() => setHover(null), 260)
  }, [cancelClose])
  useEffect(() => cancelClose, [cancelClose])
  // Filtering is applied to the source, so the closure, the count and the
  // drawing all agree on which declarations exist.
  const shown = useMemo(() => filterSource(source, accept ?? null), [source, accept])
  // The size of the whole closure, not of the part that fits on the canvas.
  // A small closure is counted during render and costs nothing; a large one
  // finishes in slices, so that a depth change neither stalls nor forces the
  // whole graph to re-render twice more just to fill in a number.
  const counted = useMemo(
    () => beginClosureSize(shown, root, depth, direction),
    [shown, root, depth, direction],
  )
  const [slowTotal, setSlowTotal] = useState<ClosureSize | null>(null)
  useEffect(() => {
    if (counted.done) return
    let cancelled = false
    setSlowTotal(null)
    counted.rest(() => cancelled).then((size) => {
      if (!cancelled && size) setSlowTotal(size)
    })
    return () => {
      cancelled = true
    }
  }, [counted])
  const total = counted.done ? counted.size : slowTotal

  const { graph, width, height, geometry } = useMemo(() => {
    const full = closure(shown, root, depth, direction, options.maxNodes, options.maxEdges)
    const graph = restrictToKinds(full, options.showStatement, options.showBody)
    const { placed, width, height } = layout(graph, options)
    const byId = new Map(placed.map((p) => [p.id, p]))

    // What lies *below* something you have vouched for is what gets muted, not
    // the trusted declaration itself.  A trusted node appearing in some other
    // declaration's graph is still a real dependency of it and reads normally;
    // it is the things underneath — already covered by the judgement — that
    // recede.  Focusing a trusted declaration therefore mutes its whole
    // dependency graph, which is the case this is really for.
    const beneathTrusted = new Set<NodeId>()
    const outgoing = new Map<NodeId, NodeId[]>()
    for (const edge of graph.edges) {
      const list = outgoing.get(edge.src)
      if (list) list.push(edge.tgt)
      else outgoing.set(edge.src, [edge.tgt])
    }
    const queue = graph.nodes.filter((n) => isTrusted?.(n.id)).map((n) => n.id)
    while (queue.length > 0) {
      for (const target of outgoing.get(queue.pop()!) ?? []) {
        // A trusted node is never dimmed, even when something below another
        // trusted node reaches it.  `Nat.gcd` is characterized by theorems that
        // state facts *about* `Nat.gcd`, so it is reachable from itself; without
        // this it would dim itself.
        if (beneathTrusted.has(target) || isTrusted?.(target)) continue
        beneathTrusted.add(target)
        queue.push(target)
      }
    }

    // Everything on a path through the selection: what it rests on, all the way
    // down, and what rests on it, all the way up.  Following the edges *both*
    // ways from the same walk would instead spread across the whole drawing —
    // a sibling sharing one dependency is not connected to this node in any
    // sense worth drawing — so the two directions are walked separately and
    // each only ever moves one way.
    const connected = new Set<NodeId>([selected])
    if (dimUnconnected) {
      const incoming = new Map<NodeId, NodeId[]>()
      for (const edge of graph.edges) {
        const list = incoming.get(edge.tgt)
        if (list) list.push(edge.src)
        else incoming.set(edge.tgt, [edge.src])
      }
      for (const step of [outgoing, incoming]) {
        const queue = [selected]
        while (queue.length > 0) {
          for (const next of step.get(queue.pop()!) ?? []) {
            if (connected.has(next)) continue
            connected.add(next)
            queue.push(next)
          }
        }
      }
    }


    // Everything that does not depend on the selection is computed once here,
    // so that selecting a node only changes two className strings.
    const edges = graph.edges.flatMap((edge, i) => {
      const from = byId.get(edge.src)
      const to = byId.get(edge.tgt)
      if (!from || !to) return []
      // Edges leave the face of the node that points at the next layer, so a
      // rotated graph gets rotated connectors rather than ones cutting across it.
      const sideways = options.orientation === 'horizontal'
      const x1 = sideways ? from.x + options.nodeWidth : from.x + options.nodeWidth / 2
      const y1 = sideways ? from.y + NODE_HEIGHT / 2 : from.y + NODE_HEIGHT
      const x2 = sideways ? to.x : to.x + options.nodeWidth / 2
      const y2 = sideways ? to.y + NODE_HEIGHT / 2 : to.y
      const mid = sideways ? (x1 + x2) / 2 : (y1 + y2) / 2
      return [
        {
          key: i,
          src: edge.src,
          tgt: edge.tgt,
          kind: edge.kind as string,
          dim: options.dimBeneathTrusted && beneathTrusted.has(edge.tgt),
          // Lit whenever both ends are on a path through the selection.  Keying
          // this off the selection's *direct* edges instead left the connected
          // nodes lit but the edges between them almost invisible, which drew a
          // constellation rather than a subgraph.
          offPath: dimUnconnected && !(connected.has(edge.src) && connected.has(edge.tgt)),
          d: sideways
            ? `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`
            : `M ${x1} ${y1} C ${x1} ${mid}, ${x2} ${mid}, ${x2} ${y2}`,
        },
      ]
    })

    const nodes = placed.map((p) => {
      const decl = source.node(p.id)
      const trusted = isTrusted?.(p.id) ?? false
      const dimmed = options.dimBeneathTrusted && beneathTrusted.has(p.id)
      const isNodeHidden = isHidden?.(p.id) ?? false
      return {
        id: p.id,
        x: p.x,
        y: p.y,
        label: labelFor(decl.name, options),
        title:
          `${decl.name}\n${decl.module}\n${decl.kind}${decl.isData ? ' (data)' : ' (proof)'}` +
          (trusted ? '\ntrusted' : '') +
          (dimmed ? '\nbelow a trusted declaration' : ''),
        classes: [
          'node',
          decl.isData ? 'data' : 'prop',
          decl.kind === 'axiom' ? 'axiom' : '',
          p.id === root ? 'root' : '',
          trusted ? 'trusted' : '',
          dimmed ? 'beneath-trusted' : '',
          isNodeHidden ? 'hidden-decl' : '',
          dimUnconnected && !connected.has(p.id) ? 'unconnected' : '',
        ].join(' '),
        onClick: () => onSelect(p.id),
        onDoubleClick: () => onFocus(p.id),
        onEnter: (event: ReactMouseEvent) => {
          cancelClose()
          setHover({ id: p.id, x: event.clientX, y: event.clientY })
        },
      }
    })

    return { graph, width, height, geometry: { edges, nodes } }
  }, [shown, source, root, depth, direction, onSelect, onFocus, isTrusted, isHidden, options, selected, dimUnconnected, cancelClose])

  useEffect(() => {
    onStats?.({
      total,
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      truncated: graph.truncated === true,
    })
  }, [onStats, total, graph])

  return (
    <div className="graph-scroll">
      {/*
        Wide closures are common — a single definition can pull in dozens of
        instances at one layer — so the canvas is scaled to the pane rather than
        overflowing it, which would push the root out of view.
      */}
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="xMidYMin meet"
        style={fit ? { width: '100%', height: 'auto' } : { width, height }}
        role="img"
        aria-label="dependency graph"
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" className="arrowhead" />
          </marker>
        </defs>
        {geometry.edges.map((edge) => (
          <GraphEdge
            key={edge.key}
            d={edge.d}
            kind={edge.kind}
            highlight={edge.src === selected || edge.tgt === selected}
            dim={edge.dim}
            offPath={edge.offPath}
          />
        ))}
        {geometry.nodes.map((node) => (
          <GraphNode
            key={node.id}
            x={node.x}
            y={node.y}
            width={options.nodeWidth}
            label={node.label}
            title={node.title}
            classes={`${node.classes}${node.id === selected ? ' selected' : ''}`}
            onClick={node.onClick}
            onDoubleClick={node.onDoubleClick}
            onEnter={node.onEnter}
            onLeave={scheduleClose}
          />
        ))}
      </svg>
      {hover && (
        <NodePreview
          source={source}
          id={hover.id}
          x={hover.x}
          y={hover.y}
          hidden={isHidden?.(hover.id) ?? false}
          onPointerEnter={cancelClose}
          onPointerLeave={scheduleClose}
          onHide={(name) => {
            onHide?.(name)
            setHover(null)
          }}
          onUnhide={(name) => {
            onUnhide?.(name)
            setHover(null)
          }}
        />
      )}
      <div className="graph-caption">
        {/* The totals are the whole closure; the graph itself is capped at what
            can be laid out legibly, so say so rather than reporting the cap. */}
        {total === null ? (
          <span className="counting">counting…</span>
        ) : (
          <>
            {total.complete ? '' : '≥ '}
            {total.nodes.toLocaleString()} nodes · {total.complete ? '' : '≥ '}
            {total.edges.toLocaleString()} edges
          </>
        )}{' '}
        · depth {depth}
        {graph.truncated && (
          <span
            className="truncated"
            title="The closure is larger than the graph can lay out; the drawing shows part of it."
          >
            {' '}
            · showing {graph.nodes.length.toLocaleString()} nodes,{' '}
            {graph.edges.length.toLocaleString()} edges
          </span>
        )}
        {/* The expanded view has a legend of its own in its bar; a second copy
            under a canvas that is metres tall helps nobody. */}
        {fit && <GraphLegend compact />}
      </div>
    </div>
  )
}