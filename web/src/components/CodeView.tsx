import type { CodeBlock, CodeRef } from '../data/types'

/**
 * Lean keywords worth colouring in delaborated output.
 *
 * This is deliberately lexical and cosmetic.  The *semantic* half — which
 * constant a token denotes — comes from the delaborator via `CodeBlock.refs`,
 * because only Lean can resolve that through notation and instances.
 */
const KEYWORDS = new Set([
  'def',
  'theorem',
  'axiom',
  'opaque',
  'inductive',
  'abbrev',
  'instance',
  'structure',
  'class',
  'fun',
  'let',
  'have',
  'match',
  'with',
  'do',
  'if',
  'then',
  'else',
  'Type',
  'Sort',
  'Prop',
])

type Piece =
  | { kind: 'ref'; text: string; ref: CodeRef }
  | { kind: 'plain'; text: string }

/** Split the text at reference boundaries.  Refs never overlap; Lean prunes them. */
function split(block: CodeBlock): Piece[] {
  const refs = [...block.refs].sort((a, b) => a.start - b.start)
  const pieces: Piece[] = []
  let cursor = 0
  for (const ref of refs) {
    if (ref.start < cursor) continue
    if (ref.start > cursor) pieces.push({ kind: 'plain', text: block.text.slice(cursor, ref.start) })
    pieces.push({ kind: 'ref', text: block.text.slice(ref.start, ref.stop), ref })
    cursor = ref.stop
  }
  if (cursor < block.text.length) pieces.push({ kind: 'plain', text: block.text.slice(cursor) })
  return pieces
}

/** Colour keywords, numbers and binders inside a stretch of untagged text. */
function highlightPlain(text: string, key: string) {
  // Split into words, numbers and everything else, keeping the separators.
  const tokens = text.split(/([A-Za-z_][A-Za-z0-9_'!?.]*|\d+)/g)
  return tokens.map((token, i) => {
    if (token.length === 0) return null
    if (KEYWORDS.has(token)) {
      return (
        <span key={`${key}-${i}`} className="tok-keyword">
          {token}
        </span>
      )
    }
    if (/^\d+$/.test(token)) {
      return (
        <span key={`${key}-${i}`} className="tok-literal">
          {token}
        </span>
      )
    }
    return <span key={`${key}-${i}`}>{token}</span>
  })
}

interface CodeViewProps {
  block: CodeBlock
  /** Called with a constant name when its token is clicked. */
  onSelectName: (name: string) => void
  /** Whether a name is present in the index, and so worth making clickable. */
  isKnown: (name: string) => boolean
}

/** Rendered Lean code in which constants can be clicked to focus them. */
export function CodeView({ block, onSelectName, isKnown }: CodeViewProps) {
  return (
    <pre className="code">
      <code>
        {split(block).map((piece, i) => {
          if (piece.kind === 'plain') return <span key={i}>{highlightPlain(piece.text, String(i))}</span>
          // Internal declarations such as `Nat.gcd._unary` are traversed by the
          // exporter but never given a node, so they render as plain constants.
          const known = isKnown(piece.ref.name)
          return (
            <span
              key={i}
              className={`tok-const ${known ? 'known' : ''}`}
              title={known ? `${piece.ref.name} — click to focus` : piece.ref.name}
              onClick={known ? () => onSelectName(piece.ref.name) : undefined}
            >
              {piece.text}
            </span>
          )
        })}
      </code>
    </pre>
  )
}