import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { Accept, GraphSource } from '../data/source'
import type { NodeId } from '../data/types'
import type { HiddenConfig } from '../data/hidden'
import { EXPANDED_OPTIONS, GraphView, type GraphOptions } from './GraphView'
import { GraphLegend } from './GraphLegend'
import type { ClosureSize } from '../data/source'
import type { Direction } from './DepsTree'

interface ExpandedGraphProps {
  source: GraphSource
  root: NodeId
  rootName: string
  direction: Direction
  depth: number
  selected: NodeId
  onSelect: (id: NodeId) => void
  onFocus: (id: NodeId) => void
  dimUnconnected?: boolean
  onDirection: (direction: Direction) => void
  onDepth: (depth: number) => void
  isTrusted?: (id: NodeId) => boolean
  accept?: Accept
  isHidden?: (id: NodeId) => boolean
  onHide: (name: string) => void
  onUnhide: (name: string) => void
  /** Repositories present in the index, and which of them to draw. */
  repos: string[]
  repoFilter: Set<string>
  onRepoFilter: (next: Set<string>) => void
  hidden: HiddenConfig
  onHiddenChange: (next: HiddenConfig) => void
  onClose: () => void
}

/** A labelled slider, since most of the controls here are one. */
function Slider({
  label,
  value,
  min,
  max,
  step = 1,
  format,
  onChange,
}: {
  label: string
  value: number
  min: number
  max: number
  step?: number
  format?: (value: number) => string
  onChange: (value: number) => void
}) {
  return (
    <label className="graph-control">
      <span className="graph-control-label">{label}</span>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      <span className="graph-control-value">{format ? format(value) : value}</span>
    </label>
  )
}

/**
 * The graph, full screen, with the presentation opened up.
 *
 * The side pane has to fit beside everything else, so it caps the canvas width
 * and wraps wide layers onto several rows.  Here there is no such constraint:
 * a layer runs as wide as it needs and the canvas scrolls, which is the only
 * way to see the actual shape of a wide dependency graph.
 *
 * Not a second renderer — the same `GraphView` with different `GraphOptions`,
 * so anything fixed in one is fixed in both.
 */
export function ExpandedGraph({
  source,
  root,
  rootName,
  direction,
  depth,
  selected,
  onSelect,
  onFocus,
  dimUnconnected,
  onDirection,
  onDepth,
  isTrusted,
  accept,
  isHidden,
  onHide,
  onUnhide,
  repos,
  repoFilter,
  onRepoFilter,
  hidden,
  onHiddenChange,
  onClose,
}: ExpandedGraphProps) {
  const [options, setOptions] = useState<GraphOptions>(EXPANDED_OPTIONS)
  const [zoom, setZoom] = useState(1)
  // The caption sits under a canvas that is usually scrolled well out of view,
  // so the counts are repeated up here where the controls that change them are.
  const [stats, setStats] = useState<{
    total: ClosureSize | null
    nodes: number
    edges: number
    truncated: boolean
  } | null>(null)
  const onStats = useCallback(
    (next: { total: ClosureSize | null; nodes: number; edges: number; truncated: boolean }) =>
      setStats(next),
    [],
  )
  const set = <K extends keyof GraphOptions>(key: K, value: GraphOptions[K]) =>
    setOptions((current) => ({ ...current, [key]: value }))

  // Escape closes, so leaving never needs the mouse to find a button.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // The page behind must not scroll while this is over it.
  useEffect(() => {
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [])

  // A layer is centred on the canvas, so a canvas several screens across opens
  // looking at empty margin.  Start in the middle of whichever axis the layers
  // are centred on — which the rotation swaps.
  const canvas = useRef<HTMLDivElement | null>(null)
  useLayoutEffect(() => {
    const element = canvas.current
    if (!element) return
    if (options.orientation === 'horizontal') {
      element.scrollLeft = 0
      element.scrollTop = Math.max(0, (element.scrollHeight - element.clientHeight) / 2)
    } else {
      element.scrollTop = 0
      element.scrollLeft = Math.max(0, (element.scrollWidth - element.clientWidth) / 2)
    }
  }, [options, zoom, root, depth, direction])

  return (
    <div className="graph-expanded" role="dialog" aria-modal="true" aria-label="expanded graph">
      <header className="graph-expanded-bar">
        <button className="back" onClick={onClose} title="Back to the declaration (Esc)">
          ← back
        </button>
        <span className="graph-expanded-title">{rootName}</span>
        {stats && (
          <span className="graph-expanded-stats">
            {stats.total
              ? `${stats.total.complete ? '' : '≥ '}${stats.total.nodes.toLocaleString()} nodes · ${
                  stats.total.complete ? '' : '≥ '
                }${stats.total.edges.toLocaleString()} edges`
              : 'counting…'}
            {stats.truncated && (
              <span className="truncated">
                {' '}
                · drawing {stats.nodes.toLocaleString()}/{stats.edges.toLocaleString()}
              </span>
            )}
          </span>
        )}

        <div className="graph-controls">
          <div className="graph-control-group">
            <button
              className={direction === 'dependencies' ? 'on' : ''}
              onClick={() => onDirection('dependencies')}
            >
              ↓ dependencies
            </button>
            <button
              className={direction === 'dependents' ? 'on' : ''}
              onClick={() => onDirection('dependents')}
            >
              ↑ dependents
            </button>
          </div>

          <Slider label="depth" value={depth} min={1} max={8} onChange={onDepth} />
          <Slider
            label="nodes"
            value={options.maxNodes}
            min={50}
            max={2000}
            step={50}
            onChange={(v) => set('maxNodes', v)}
          />
          <Slider
            label="edges"
            value={options.maxEdges}
            min={100}
            max={6000}
            step={100}
            onChange={(v) => set('maxEdges', v)}
          />
          <Slider
            label="node width"
            value={options.nodeWidth}
            min={70}
            max={340}
            step={10}
            format={(v) => `${v}px`}
            onChange={(v) => set('nodeWidth', v)}
          />
          <Slider
            label="row gap"
            value={options.layerGap}
            min={40}
            max={200}
            step={2}
            format={(v) => `${v}px`}
            onChange={(v) => set('layerGap', v)}
          />
          <Slider
            label="node gap"
            value={options.nodeGap}
            min={4}
            max={80}
            step={2}
            format={(v) => `${v}px`}
            onChange={(v) => set('nodeGap', v)}
          />
          <Slider
            label="zoom"
            value={zoom}
            min={0.2}
            max={2}
            step={0.05}
            format={(v) => `${Math.round(v * 100)}%`}
            onChange={setZoom}
          />

          <label className="graph-control">
            <span className="graph-control-label">labels</span>
            <select
              value={options.labels}
              onChange={(e) => set('labels', e.target.value as GraphOptions['labels'])}
            >
              <option value="truncated">fit to node</option>
              <option value="short">last component</option>
              <option value="full">full name</option>
            </select>
          </label>

          <div className="graph-control-group">
            <button
              className={options.orientation === 'vertical' ? 'on' : ''}
              onClick={() => set('orientation', 'vertical')}
              title="Root at the top, layers running down"
            >
              ↓ vertical
            </button>
            <button
              className={options.orientation === 'horizontal' ? 'on' : ''}
              onClick={() => set('orientation', 'horizontal')}
              title="Turned a quarter turn: layers running left to right"
            >
              → rotate 90°
            </button>
          </div>

          <label className="graph-control">
            <span
              className="graph-control-label"
              title="Only applies to the vertical layout; on its side a layer runs down the page, which scrolls."
            >
              width
            </span>
            <select
              disabled={options.orientation === 'horizontal'}
              value={options.canvasWidth === null ? 'free' : String(options.canvasWidth)}
              onChange={(e) =>
                set('canvasWidth', e.target.value === 'free' ? null : Number(e.target.value))
              }
            >
              <option value="free">unbounded</option>
              <option value="1600">wrap at 1600px</option>
              <option value="1200">wrap at 1200px</option>
              <option value="980">wrap at 980px</option>
            </select>
          </label>

          <div className="graph-control-group">
            <span className="graph-control-label">repositories</span>
            {repos.map((repo) => (
              <button
                key={repo}
                className={repoFilter.size === 0 || repoFilter.has(repo) ? 'on' : ''}
                onClick={() => {
                  const next = new Set(repoFilter)
                  if (next.has(repo)) next.delete(repo)
                  else next.add(repo)
                  onRepoFilter(next)
                }}
                title={`Draw declarations from ${repo}`}
              >
                {repo}
              </button>
            ))}
            {repoFilter.size > 0 && (
              <button onClick={() => onRepoFilter(new Set())} title="Draw every repository">
                all
              </button>
            )}
          </div>

          <div className="graph-control-group">
            <button
              className={hidden.active ? 'on' : ''}
              onClick={() => onHiddenChange({ ...hidden, active: !hidden.active })}
              title="Leave out declarations you have hidden"
            >
              hide hidden ({hidden.names.length})
            </button>
            {hidden.names.length > 0 && (
              <button
                onClick={() => onHiddenChange({ ...hidden, names: [] })}
                title="Stop hiding everything"
              >
                clear
              </button>
            )}
          </div>

          <div className="graph-control-group">
            <button
              className={options.showStatement ? 'on' : ''}
              onClick={() => set('showStatement', !options.showStatement)}
              title="Edges from a declaration's statement"
            >
              statement
            </button>
            <button
              className={options.showBody ? 'on' : ''}
              onClick={() => set('showBody', !options.showBody)}
              title="Edges from a declaration's body or proof term"
            >
              body
            </button>
            <button
              className={options.dimBeneathTrusted ? 'on' : ''}
              onClick={() => set('dimBeneathTrusted', !options.dimBeneathTrusted)}
              title="Mute what sits below a trusted declaration"
            >
              dim trusted
            </button>
            <button onClick={() => setOptions(EXPANDED_OPTIONS)} title="Restore the defaults">
              reset
            </button>
          </div>
        </div>
      </header>

      <GraphLegend />
      <div className="graph-expanded-canvas" ref={canvas}>
        {/* Zoom is applied here rather than inside the SVG so that the layout
            is unaffected by it: what you see scaled is what would print. */}
        <div style={{ transform: `scale(${zoom})`, transformOrigin: 'top left' }}>
          <GraphView
            source={source}
            root={root}
            direction={direction}
            depth={depth}
            selected={selected}
            onSelect={onSelect}
            onFocus={onFocus}
            dimUnconnected={dimUnconnected}
            isTrusted={isTrusted}
            accept={accept}
            isHidden={isHidden}
            onHide={onHide}
            onUnhide={onUnhide}
            options={options}
            onStats={onStats}
            fit={false}
          />
        </div>
      </div>
    </div>
  )
}
