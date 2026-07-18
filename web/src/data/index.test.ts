import { beforeAll, describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { StaticIndexSource, closure } from './source'

/**
 * Checks the data layer against a real exported index rather than fixtures, so
 * that a change to the Lean exporter's output cannot silently diverge from what
 * the frontend expects.
 *
 * Generate the index first:
 *   trust export --repo core --out web/public/index Init
 */
const base = new URL('../../public/index/core/', import.meta.url).pathname
const available = existsSync(`${base}stmt-edges.bin`)
const suite = available ? describe : describe.skip

suite('exported index', () => {
  // Loaded in `beforeAll` rather than in the suite body: `describe.skip` still
  // runs its callback to collect tests, so reading files here would throw when
  // no index has been generated instead of skipping.
  let source: StaticIndexSource

  beforeAll(() => {
    // Edges are flat int32 pairs on disk, exactly as the browser consumes them.
    const pairs = (path: string): Int32Array => {
      if (!existsSync(path)) return new Int32Array(0)
      const buffer = readFileSync(path)
      return new Int32Array(buffer.buffer, buffer.byteOffset, buffer.byteLength >> 2)
    }
    source = StaticIndexSource.fromParts(
      readFileSync(`${base}meta.json`, 'utf8'),
      readFileSync(`${base}decls.jsonl`, 'utf8'),
      pairs(`${base}stmt-edges.bin`),
      pairs(`${base}body-edges.bin`),
    )
  })

  it('ranks an exact match first even at limit 1', () => {
    // `search('Eq', 1)` used to return `eq_of_heq`, so `?decl=Eq` opened the
    // wrong declaration.
    expect(source.search('Eq', 1)[0].name).toBe('Eq')
    expect(source.search('Nat', 1)[0].name).toBe('Nat')
  })

  it('agrees with its own metadata on the declaration count', () => {
    expect(source.meta().schemaVersion).toBe(1)
    expect(source.meta().declCount).toBeGreaterThan(0)
  })

  it('reports the same statement dependencies for Nat.gcd as the Lean side', () => {
    const gcd = source.search('Nat.gcd', 1)[0]
    expect(gcd.name).toBe('Nat.gcd')
    expect(gcd.isData).toBe(true)
    const statement = source.dependencyEdges(gcd.id).filter((e) => e.kind === 'statement')
    expect(statement.map((e) => source.node(e.id).name)).toEqual(['Nat'])
  })

  it('unfolds Nat.gcd through its body, matching `trust deps`', () => {
    // `trust deps Init.Data.Nat.Gcd Nat.gcd` reports 106 nodes; the browser-side
    // closure applies the same rule and must land in the same neighbourhood.
    const gcd = source.search('Nat.gcd', 1)[0]
    const names = new Set(closure(source, gcd.id, 12, 'dependencies', 500).nodes.map((n) => n.name))
    expect(names.has('WellFounded.Nat.fix')).toBe(true)
    expect(names.has('InvImage')).toBe(true)
    // Proof-internal lemmas of gcd's termination argument must not be reached.
    expect(names.has('Nat.ble_eq_true_of_le')).toBe(false)
  })

  it('finds declarations that depend on Nat.gcd', () => {
    const gcd = source.search('Nat.gcd', 1)[0]
    expect(source.dependents(gcd.id).length).toBeGreaterThan(0)
  })

  it('classifies a theorem as a proof', () => {
    const thm = source.search('Nat.succ_ne_zero', 1)[0]
    expect(thm.isProp).toBe(true)
    expect(thm.isData).toBe(false)
  })

  it('expands a closure within its node budget, with no dangling edges', () => {
    const thm = source.search('Nat.succ_ne_zero', 1)[0]
    const graph = closure(source, thm.id, 4, 'dependencies', 200)
    expect(graph.nodes.length).toBeGreaterThan(1)
    expect(graph.nodes.length).toBeLessThanOrEqual(201)
    const ids = new Set(graph.nodes.map((n) => n.id))
    for (const edge of graph.edges) {
      expect(ids.has(edge.src) && ids.has(edge.tgt)).toBe(true)
    }
  })
})