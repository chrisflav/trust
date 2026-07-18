import { describe, expect, it } from 'vitest'
import { StaticIndexSource, closure } from './source'
import { pathTo, trustedCutSource } from './trustedMode'
import { indexMarks } from './marks'
import type { Marks } from './types'

const meta = JSON.stringify({
  schemaVersion: 1,
  repo: 'test',
  rev: 'abc',
  toolchain: '4.31.0',
  moduleCount: 1,
  declCount: 6,
  stmtEdgeCount: 5,
  bodyEdgeCount: 0,
  hasBodyEdges: false,
})

function decl(id: number, name: string, isProp = false): string {
  return JSON.stringify({
    id,
    name,
    module: 'Mathlib.A',
    kind: isProp ? 'theorem' : 'def',
    isProp,
    isData: !isProp,
  })
}

//  Root → Mid → Deep → Bottom, plus a theorem that characterizes Mid.
const decls = [
  decl(0, 'Root'),
  decl(1, 'Mid'),
  decl(2, 'Deep'),
  decl(3, 'Bottom'),
  decl(4, 'Mid.ext', true),
  decl(5, 'Aside'),
].join('\n')

const edges = [
  { src: 0, tgt: 1 },
  { src: 1, tgt: 2 },
  { src: 2, tgt: 3 },
  { src: 4, tgt: 5 },
]
  .map((e) => JSON.stringify(e))
  .join('\n')

const base = StaticIndexSource.fromText(meta, decls, edges)

function marksWith(partial: Partial<Marks>) {
  return indexMarks(
    { version: 1, trusted: [], characterizations: [], protectedDecls: [], ...partial },
    false,
  )
}

describe('up to trusted', () => {
  it('leaves the index alone when nothing is marked', () => {
    const cut = trustedCutSource(base, marksWith({}), 0)
    expect(cut.dependencies(1)).toEqual([2])
    expect(cut.degree(1, 'dependencies')).toBe(1)
  })

  it('makes a trusted declaration a leaf', () => {
    const cut = trustedCutSource(
      base,
      marksWith({ trusted: [{ name: 'Mid', commit: 'abc', note: '' }] }),
      0,
    )
    expect(cut.dependencies(1)).toEqual([])
    expect(cut.degree(1, 'dependencies')).toBe(0)
    // The trusted node is still reached and still shown; only what is below it
    // is cut away.
    expect(cut.dependencies(0)).toEqual([1])
  })

  it('exempts the root, so focusing a trusted declaration still shows its tree', () => {
    const cut = trustedCutSource(
      base,
      marksWith({ trusted: [{ name: 'Mid', commit: 'abc', note: '' }] }),
      1,
    )
    expect(cut.dependencies(1)).toEqual([2])
  })

  it('stops the graph closure at a trusted declaration', () => {
    const marks = marksWith({ trusted: [{ name: 'Mid', commit: 'abc', note: '' }] })
    expect(closure(base, 0, 8).nodes.map((n) => n.name).sort()).toEqual([
      'Bottom',
      'Deep',
      'Mid',
      'Root',
    ])
    const cut = trustedCutSource(base, marks, 0)
    expect(closure(cut, 0, 8).nodes.map((n) => n.name).sort()).toEqual(['Mid', 'Root'])
  })

  it('replaces a characterized definition by its characterising theorems', () => {
    const cut = trustedCutSource(
      base,
      marksWith({
        characterizations: [{ definition: 'Mid', theorems: ['Mid.ext'], note: '' }],
      }),
      0,
    )
    expect(cut.dependencies(1)).toEqual([4])
    // and the tree carries on through the theorem's own dependencies
    expect(cut.dependencies(4)).toEqual([5])
    expect(closure(cut, 0, 8).nodes.map((n) => n.name).sort()).toEqual([
      'Aside',
      'Mid',
      'Mid.ext',
      'Root',
    ])
  })

  it('applies characterization at the root too', () => {
    const cut = trustedCutSource(
      base,
      marksWith({ characterizations: [{ definition: 'Mid', theorems: ['Mid.ext'], note: '' }] }),
      1,
    )
    expect(cut.dependencies(1)).toEqual([4])
  })

  it('prefers characterization over the trusted cut', () => {
    const cut = trustedCutSource(
      base,
      marksWith({
        trusted: [{ name: 'Mid', commit: 'abc', note: '' }],
        characterizations: [{ definition: 'Mid', theorems: ['Mid.ext'], note: '' }],
      }),
      0,
    )
    expect(cut.dependencies(1)).toEqual([4])
  })

  it('ignores theorems the index does not contain', () => {
    const cut = trustedCutSource(
      base,
      marksWith({
        characterizations: [{ definition: 'Mid', theorems: ['Nope', 'Mid.ext'], note: '' }],
      }),
      0,
    )
    expect(cut.dependencies(1)).toEqual([4])
  })

  it('never changes the dependents direction', () => {
    const cut = trustedCutSource(
      base,
      marksWith({ trusted: [{ name: 'Mid', commit: 'abc', note: '' }] }),
      0,
    )
    expect(cut.dependents(2)).toEqual(base.dependents(2))
    expect(cut.degree(2, 'dependents')).toBe(base.degree(2, 'dependents'))
  })
})

describe('pathTo', () => {
  it('finds the route the tree has to open', () => {
    expect(pathTo(base, 0, 3, 'dependencies')).toEqual([0, 1, 2, 3])
  })

  it('is just the root when the target is the root', () => {
    expect(pathTo(base, 0, 0, 'dependencies')).toEqual([0])
  })

  it('returns null when the target is out of reach', () => {
    expect(pathTo(base, 0, 5, 'dependencies')).toBeNull()
  })

  it('respects the depth bound', () => {
    expect(pathTo(base, 0, 3, 'dependencies', 2)).toBeNull()
  })

  it('follows the cut source, so a cut-off node is unreachable', () => {
    const cut = trustedCutSource(
      base,
      marksWith({ trusted: [{ name: 'Mid', commit: 'abc', note: '' }] }),
      0,
    )
    expect(pathTo(cut, 0, 3, 'dependencies')).toBeNull()
    expect(pathTo(cut, 0, 1, 'dependencies')).toEqual([0, 1])
  })
})
