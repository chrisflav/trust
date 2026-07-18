/**
 * What the colours in the graph mean.
 *
 * The drawing carries five independent signals at once — what kind of
 * declaration it is, whether it is the root, whether it is selected, whether
 * you trust it, and whether it sits below something you trust — and they are
 * split across the border and the background so they can be read together.
 * That is only legible if it is written down somewhere.
 */
export function GraphLegend({ compact = false }: { compact?: boolean }) {
  return (
    <div className={compact ? 'graph-legend compact' : 'graph-legend'}>
      <div className="legend-group">
        <span className="legend-heading">border</span>
        <span className="legend-item">
          <span className="legend-swatch data" /> data
        </span>
        <span className="legend-item">
          <span className="legend-swatch prop" /> proof
        </span>
        <span className="legend-item">
          <span className="legend-swatch axiom" /> axiom
        </span>
        <span className="legend-item">
          <span className="legend-swatch selected" /> selected
        </span>
        <span className="legend-item">
          <span className="legend-swatch dashed" /> below trusted
        </span>
      </div>
      <div className="legend-group">
        <span className="legend-heading">background</span>
        <span className="legend-item">
          <span className="legend-swatch fill-trusted" /> trusted
        </span>
        <span className="legend-item">
          <span className="legend-swatch fill-root" /> root
        </span>
      </div>
      <div className="legend-group">
        <span className="legend-heading">edges</span>
        <span className="legend-item">
          <span className="legend-line statement" /> statement
        </span>
        <span className="legend-item">
          <span className="legend-line body" /> body
        </span>
      </div>
    </div>
  )
}
