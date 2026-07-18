import type { Decl } from '../data/types'

const SHORT: Record<string, string> = {
  axiom: 'ax',
  def: 'def',
  theorem: 'thm',
  opaque: 'opq',
  quot: 'quot',
  inductive: 'ind',
  ctor: 'ctor',
  recursor: 'rec',
}

/** The declaration kind, coloured by whether the declaration carries data. */
export function KindBadge({ decl }: { decl: Decl }) {
  const className = decl.kind === 'axiom' ? 'axiom' : decl.isData ? 'data' : 'prop'
  return (
    <span className={`badge ${className}`} title={decl.isData ? 'data-carrying' : 'proof'}>
      {SHORT[decl.kind] ?? decl.kind}
    </span>
  )
}