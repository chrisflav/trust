import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import type { GraphSource } from '../data/source'
import type { DeclCode, NodeId } from '../data/types'

interface NodePreviewProps {
  source: GraphSource
  id: NodeId
  /** Where the pointer was, in client coordinates. */
  x: number
  y: number
  hidden: boolean
  onHide: (name: string) => void
  onUnhide: (name: string) => void
  /** Keep the card open while the pointer is on it, so its buttons are usable. */
  onPointerEnter: () => void
  onPointerLeave: () => void
}

const WIDTH = 460

/**
 * What a declaration says, shown where the pointer is.
 *
 * A node in the graph is a hundred and fifty pixels of elided name, which is
 * enough to find something and not nearly enough to judge it.  The docstring
 * and signature are what actually answer "is this what I think it is", and both
 * are already in the index — the code shard is fetched on demand, so hovering
 * one node costs one shard the reader was likely to need anyway.
 */
export function NodePreview({
  source,
  id,
  x,
  y,
  hidden,
  onHide,
  onUnhide,
  onPointerEnter,
  onPointerLeave,
}: NodePreviewProps) {
  const [code, setCode] = useState<DeclCode | null>(null)
  const decl = source.node(id)

  useEffect(() => {
    let current = true
    setCode(null)
    source.code(id).then((loaded) => {
      if (current) setCode(loaded)
    })
    return () => {
      current = false
    }
  }, [source, id])

  if (!decl) return null

  // Kept inside the viewport: a node near the right edge would otherwise put
  // its preview off screen, which is exactly where the long names are.
  const left = Math.min(x + 16, window.innerWidth - WIDTH - 16)
  const flipAbove = y > window.innerHeight - 260
  const style = {
    left: Math.max(8, left),
    top: flipAbove ? undefined : y + 18,
    bottom: flipAbove ? window.innerHeight - y + 18 : undefined,
    width: WIDTH,
  }

  // Rendered into `document.body` rather than in place.  The expanded view
  // scales its canvas with a CSS transform, and a transformed ancestor becomes
  // the containing block for `position: fixed` — so in place, the preview was
  // positioned relative to the zoomed canvas and scaled along with it, landing
  // nowhere near the cursor.
  return createPortal(
    <div
      className="node-preview"
      style={style}
      role="tooltip"
      onMouseEnter={onPointerEnter}
      onMouseLeave={onPointerLeave}
    >
      <div className="node-preview-name">{decl.name}</div>
      <div className="node-preview-module">{decl.module}</div>
      {code?.doc && <p className="node-preview-doc">{code.doc}</p>}
      {code ? (
        <pre className="node-preview-code">
          <code>{code.signature.text}</code>
        </pre>
      ) : (
        <p className="node-preview-doc">Loading…</p>
      )}
      <div className="node-preview-actions">
        <span>double-click to focus</span>
        <button
          onClick={(event) => {
            event.stopPropagation()
            if (hidden) onUnhide(decl.name)
            else onHide(decl.name)
          }}
        >
          {hidden ? 'unhide' : 'hide'}
        </button>
      </div>
    </div>,
    document.body,
  )
}
