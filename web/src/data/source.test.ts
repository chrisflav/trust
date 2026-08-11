import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  StaticIndexSource,
  closure,
  closureSize,
  fetchIndexParts,
  repoOfModule,
  type LoadProgress,
} from './source'
import type { Decl } from './types'

const meta = JSON.stringify({
  schemaVersion: 1,
  repo: 'test',
  rev: 'abc',
  toolchain: '4.31.0',
  moduleCount: 2,
  declCount: 4,
  stmtEdgeCount: 4,
  bodyEdgeCount: 0,
  hasBodyEdges: false,
})

function decl(id: number, name: string, module: string, isProp = false): string {
  return JSON.stringify({
    id,
    name,
    module,
    kind: isProp ? 'theorem' : 'def',
    isProp,
    isData: !isProp,
  } satisfies Decl)
}

// 0 → 1 → 3, 0 → 2 → 3
const decls = [
  decl(0, 'Root', 'Mathlib.A'),
  decl(1, 'Left', 'Mathlib.B'),
  decl(2, 'Right', 'Init.C'),
  decl(3, 'Leaf', 'Init.C', true),
].join('\n')

const edges = ['{"src":0,"tgt":1}', '{"src":0,"tgt":2}', '{"src":1,"tgt":3}', '{"src":2,"tgt":3}'].join('\n')

// Node 0 is a def, so its body unfolds; node 3 is a theorem, so its proof term
// must never be followed.
const bodyEdges = ['{"src":0,"tgt":3}', '{"src":3,"tgt":1}'].join('\n')

describe('StaticIndexSource', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges)

  it('reads declarations', () => {
    expect(source.node(0).name).toBe('Root')
    expect(source.node(3).isProp).toBe(true)
    expect(source.meta().declCount).toBe(4)
  })

  it('builds forward adjacency', () => {
    expect(source.dependencies(0).sort()).toEqual([1, 2])
    expect(source.dependencies(3)).toEqual([])
  })

  it('builds reverse adjacency', () => {
    expect(source.dependents(3).sort()).toEqual([1, 2])
    expect(source.dependents(0)).toEqual([])
  })

  it('tolerates a trailing newline in the edge file', () => {
    const padded = StaticIndexSource.fromText(meta, `${decls}\n`, `${edges}\n`)
    expect(padded.dependencies(0).sort()).toEqual([1, 2])
  })

  it('derives repositories from module roots', () => {
    expect(source.repos()).toEqual(['Mathlib', 'core'])
    expect(source.repoOf(0)).toBe('Mathlib')
    expect(source.repoOf(2)).toBe('core')
  })

  it('ranks search results exact, then prefix, then infix', () => {
    const results = source.search('l').map((d) => d.name)
    expect(results).toContain('Left')
    expect(results).toContain('Leaf')
    expect(source.search('root')[0].name).toBe('Root')
    expect(source.search('')).toEqual([])
  })
})

describe('closure', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges)

  it('stops at the requested depth', () => {
    const shallow = closure(source, 0, 1)
    expect(shallow.nodes.map((n) => n.id).sort()).toEqual([0, 1, 2])
  })

  it('reaches the whole diamond and dedupes the shared node', () => {
    const full = closure(source, 0, 5)
    expect(full.nodes.map((n) => n.id).sort()).toEqual([0, 1, 2, 3])
    // Leaf is reached along two paths but appears once, with both edges kept.
    expect(full.edges.filter((e) => e.tgt === 3).length).toBe(2)
  })

  it('walks the reverse direction', () => {
    const up = closure(source, 3, 5, 'dependents')
    expect(up.nodes.map((n) => n.id).sort()).toEqual([0, 1, 2, 3])
    expect(up.edges).toContainEqual({ src: 1, tgt: 3, kind: 'statement' })
  })

  it('honours the node budget', () => {
    const capped = closure(source, 0, 5, 'dependencies', 2)
    expect(capped.nodes.length).toBeLessThanOrEqual(3)
  })

  it('never emits an edge to a node it did not keep', () => {
    const capped = closure(source, 0, 5, 'dependencies', 2)
    const ids = new Set(capped.nodes.map((n) => n.id))
    for (const edge of capped.edges) {
      expect(ids.has(edge.src) && ids.has(edge.tgt)).toBe(true)
    }
  })
})

describe('the definitional rule', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges, bodyEdges)

  it('unfolds a data-carrying declaration through its body', () => {
    const edges = source.dependencyEdges(0)
    expect(edges).toContainEqual({ id: 3, kind: 'body' })
    expect(edges).toContainEqual({ id: 1, kind: 'statement' })
  })

  it('never follows a proof term', () => {
    // Node 3 is a theorem whose body mentions node 1; that edge must not appear.
    expect(source.node(3).isData).toBe(false)
    expect(source.dependencies(3)).toEqual([])
  })

  it('does not duplicate a dependency present in both statement and body', () => {
    const withDuplicate = StaticIndexSource.fromText(meta, decls, edges, '{"src":0,"tgt":1}')
    expect(withDuplicate.dependencyEdges(0).filter((e) => e.id === 1)).toEqual([
      { id: 1, kind: 'statement' },
    ])
  })

  it('does not count proof-side uses as dependents', () => {
    // Node 3 is a theorem whose proof mentions node 1.  That is not a
    // dependency: a proof is a leaf in the forward direction, and the reverse
    // direction has to say the same thing, or a theorem comes out as a
    // dependent of everything its proof happened to touch.
    expect(source.dependents(1)).not.toContain(3)
    // Nodes 1 and 2 reach it through their statements, and node 0 is a
    // definition whose body does; only the proof-side use is dropped.
    expect(source.dependents(3).sort()).toEqual([0, 1, 2])
  })

  it('still unfolds a definition through its body in both directions', () => {
    // Node 0 is a def whose body uses node 3, so node 3 keeps node 0 as a
    // dependent; only *proof* bodies are dropped.
    expect(source.dependencyEdges(0)).toContainEqual({ id: 3, kind: 'body' })
    expect(source.dependents(3)).toContain(0)
  })

  it('works when no body edges were exported', () => {
    const statementOnly = StaticIndexSource.fromText(meta, decls, edges)
    expect(statementOnly.dependencies(0).sort()).toEqual([1, 2])
  })
})

describe('budgets under high fan-out', () => {
  // One declaration that 5000 others depend on, like `Eq` or `Nat` in core.
  const wideCount = 5000
  const wideDecls = [
    decl(0, 'Popular', 'Mathlib.A'),
    ...Array.from({ length: wideCount }, (_, i) => decl(i + 1, `User${i}`, 'Mathlib.B')),
  ].join('\n')
  const wideEdges = Array.from({ length: wideCount }, (_, i) =>
    JSON.stringify({ src: i + 1, tgt: 0 }),
  ).join('\n')
  const wideMeta = JSON.stringify({ ...JSON.parse(meta), declCount: wideCount + 1 })
  const source = StaticIndexSource.fromText(wideMeta, wideDecls, wideEdges)

  it('reports degree without materialising neighbours', () => {
    expect(source.degree(0, 'dependents')).toBe(wideCount)
    expect(source.degree(0, 'dependencies')).toBe(0)
  })

  it('respects the node budget even when one node exceeds it alone', () => {
    // The budget used to be checked only between nodes, so a single
    // high-fan-out declaration overshot it by orders of magnitude and the
    // graph view was handed tens of thousands of elements to render.
    const graph = closure(source, 0, 3, 'dependents', 300, 900)
    expect(graph.nodes.length).toBeLessThanOrEqual(300)
    expect(graph.edges.length).toBeLessThanOrEqual(900)
    expect(graph.truncated).toBe(true)
  })

  it('respects the edge budget', () => {
    const graph = closure(source, 0, 3, 'dependents', 10000, 50)
    expect(graph.edges.length).toBeLessThanOrEqual(50)
    expect(graph.truncated).toBe(true)
  })

  it('does not flag small closures as truncated', () => {
    const small = StaticIndexSource.fromText(meta, decls, edges)
    expect(closure(small, 0, 5).truncated).toBeFalsy()
  })
})

describe('counting', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges, bodyEdges)

  it('reports a degree equal to the number of children it lists', () => {
    // The number on a collapsed row and the number of rows it opens to are the
    // same claim; they used to disagree, because the dependency degree added
    // the statement and body degrees without deduplicating.
    for (const id of [0, 1, 2, 3]) {
      for (const direction of ['dependencies', 'dependents'] as const) {
        expect(source.degree(id, direction)).toBe(source.childEdges(id, direction).length)
      }
    }
  })

  it('counts a dependency named in both statement and body once', () => {
    const withDuplicate = StaticIndexSource.fromText(meta, decls, edges, '{"src":0,"tgt":1}')
    expect(withDuplicate.degree(0, 'dependencies')).toBe(2)
  })

  it('stops the child walk early when asked to', () => {
    const visited: number[] = []
    source.forEachChild(0, 'dependencies', (target) => {
      visited.push(target)
      return false
    })
    expect(visited).toHaveLength(1)
  })
})

describe('closureSize', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges)

  it('counts every node and edge of the closure', () => {
    const size = closureSize(source, 0, 5)
    const graph = closure(source, 0, 5)
    expect(size.nodes).toBe(graph.nodes.length)
    expect(size.edges).toBe(graph.edges.length)
    expect(size.complete).toBe(true)
  })

  describe('under a budget that truncates the drawing', () => {
    const wideCount = 5000
    const wideDecls = [
      decl(0, 'Popular', 'Mathlib.A'),
      ...Array.from({ length: wideCount }, (_, i) => decl(i + 1, `User${i}`, 'Mathlib.B')),
    ].join('\n')
    const wideEdges = Array.from({ length: wideCount }, (_, i) =>
      JSON.stringify({ src: i + 1, tgt: 0 }),
    ).join('\n')
    const wide = StaticIndexSource.fromText(
      JSON.stringify({ ...JSON.parse(meta), declCount: wideCount + 1 }),
      wideDecls,
      wideEdges,
    )

    it('reports the whole closure, not the part that was drawn', () => {
      const graph = closure(wide, 0, 3, 'dependents', 150, 400)
      const size = closureSize(wide, 0, 3, 'dependents')
      expect(graph.truncated).toBe(true)
      expect(graph.nodes.length).toBeLessThanOrEqual(150)
      // The drawing shows 150 of them; the caption has to say 5001.
      expect(size.nodes).toBe(wideCount + 1)
      expect(size.edges).toBe(wideCount)
      expect(size.complete).toBe(true)
    })

    it('reports a lower bound rather than hanging on a pathological root', () => {
      const size = closureSize(wide, 0, 3, 'dependents', 100)
      expect(size.complete).toBe(false)
      expect(size.edges).toBeLessThanOrEqual(100)
    })
  })
})

describe('search ranking', () => {
  // `aa` matches as a prefix and as an infix many times over, and the exact
  // match is the very last declaration.  Search stops scanning once the prefix
  // and infix buckets are full, so the exact match has to be found by direct
  // lookup rather than by the scan reaching it.
  const many = [
    ...Array.from({ length: 30 }, (_, i) => decl(i, `aa${i}`, 'Mathlib.A')),
    ...Array.from({ length: 30 }, (_, i) => decl(30 + i, `xaa${i}`, 'Mathlib.A')),
    decl(60, 'aa', 'Mathlib.A'),
  ].join('\n')
  const source = StaticIndexSource.fromText(
    JSON.stringify({ ...JSON.parse(meta), declCount: 61 }),
    many,
    '',
  )

  it('ranks the exact match first even when it is scanned last', () => {
    expect(source.search('aa', 5)[0].name).toBe('aa')
  })

  it('is case insensitive', () => {
    expect(source.search('AA', 5)[0].name).toBe('aa')
    expect(source.search('XAA0', 5).map((d) => d.name)).toContain('xaa0')
  })

  it('honours the limit', () => {
    expect(source.search('aa', 5)).toHaveLength(5)
  })

  it('puts prefix matches before infix matches', () => {
    const names = source.search('aa1', 40).map((d) => d.name)
    expect(names.indexOf('aa1')).toBeLessThan(names.indexOf('xaa1'))
  })

  it('lists a declaration once however often the needle occurs in it', () => {
    // `a` occurs three times in `banana`, and search scans one blob of names
    // rather than each name in turn, so it finds all three.  Reporting the
    // declaration once per occurrence put duplicate React keys in the results
    // list, which stopped it updating reliably as the query was typed.
    const repeated = [decl(0, 'banana', 'Mathlib.A'), decl(1, 'apple', 'Mathlib.A')].join('\n')
    const source = StaticIndexSource.fromText(
      JSON.stringify({ ...JSON.parse(meta), declCount: 2 }),
      repeated,
      '',
    )
    const ids = source.search('a', 40).map((d) => d.id)
    expect(ids).toHaveLength(new Set(ids).size)
    // A prefix match still outranks an infix one.
    expect(source.search('a', 40).map((d) => d.name)).toEqual(['apple', 'banana'])
  })

  it('keeps every distinct match when many names repeat the needle', () => {
    const many = Array.from({ length: 30 }, (_, i) => decl(i, `xaax${i}`, 'Mathlib.A')).join('\n')
    const source = StaticIndexSource.fromText(
      JSON.stringify({ ...JSON.parse(meta), declCount: 30 }),
      many,
      '',
    )
    const ids = source.search('a', 40).map((d) => d.id)
    expect(ids).toHaveLength(30)
    expect(new Set(ids).size).toBe(30)
  })

  it('never matches across two declaration names', () => {
    // The names are stored in one blob; a needle spanning the separator must
    // not be reported as a match.
    expect(source.search('aa29xaa0', 10)).toEqual([])
  })
})

describe('filtering during the walk', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges, bodyEdges)

  it('applies the filter while walking, not to the finished list', () => {
    // Node 0 depends on 1 (Mathlib.B) and 2 (Init.C).  Asking for one child
    // that is in `core` must return node 2, not "the first child, filtered
    // away to nothing".
    const core = source.childEdges(0, 'dependencies', 1, (id) => source.repoOf(id) === 'core')
    expect(core).toEqual([{ id: 2, kind: 'statement' }])
  })

  it('caps a filtered walk at the limit', () => {
    const all = source.childEdges(0, 'dependencies', 1, () => true)
    expect(all).toHaveLength(1)
  })

  it('returns nothing when the filter admits nothing', () => {
    expect(source.childEdges(0, 'dependencies', 50, () => false)).toEqual([])
  })

  it('filters dependents too', () => {
    // Node 3 is depended on by 1 and 2 through statements and by 0 through a
    // body edge; only node 2 lives outside Mathlib.
    const mathlib = source.childEdges(3, 'dependents', 50, (id) => source.repoOf(id) === 'Mathlib')
    expect(mathlib.map((e) => e.id).sort()).toEqual([0, 1])
  })
})

describe('name lookup and code', () => {
  const source = StaticIndexSource.fromText(meta, decls, edges)

  it('resolves a declaration name to its id', () => {
    expect(source.findByName('Leaf')).toBe(3)
  })

  it('returns null for a name the index does not contain', () => {
    // Code refs can point at internal declarations such as `Nat.gcd._unary`,
    // which the exporter traverses but never gives a node.
    expect(source.findByName('Root._unary')).toBeNull()
  })

  it('has no code when the index carries none', async () => {
    expect(await source.code(0)).toBeNull()
  })
})

/**
 * What the loading bar is told while an index arrives.
 *
 * The only thing the page can say for the minute an index takes to download is
 * how far along it is, and it used to say things that were plainly false —
 * "76.4 MB of 18.2 MB · 100%" — because the size it divided by came from a
 * `content-length` header describing the compressed bytes on the wire while the
 * bytes it counted came out of the decoder.  So these are all about where the
 * total comes from and what happens when it is not to be had.
 */
describe('load progress', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const stmtEdgeCount = 8
  const edgeBytes = stmtEdgeCount * 8
  // `∀` is three bytes of UTF-8 and one JavaScript character, so a table
  // measured in characters and a table read in bytes disagree here, as they do
  // in a real index full of `Nat.le_of_lt_succ` and `∀`-quantified statements.
  const declText = Array.from({ length: 40 }, (_, i) =>
    decl(i, `Foo.∀${i}`, 'Mathlib.A'),
  ).join('\n')
  const declBody = new TextEncoder().encode(declText)
  const served = { ...JSON.parse(meta), declCount: 40, stmtEdgeCount }

  /** A body that arrives in pieces, as a real download does. */
  function chunked(bytes: Uint8Array, pieces: number): ReadableStream<Uint8Array> {
    const size = Math.ceil(bytes.byteLength / pieces)
    return new ReadableStream({
      start(controller) {
        for (let at = 0; at < bytes.byteLength; at += size) {
          controller.enqueue(bytes.slice(at, at + size))
        }
        controller.close()
      },
    })
  }

  /**
   * Serve one index, with whatever headers the declaration table is to carry.
   *
   * The bodies are real streams rather than strings: what is under test is the
   * running count of decoded bytes, which only exists because the reader is
   * handed one chunk at a time.
   */
  function serve(
    metaJson: Record<string, unknown>,
    declHeaders: Record<string, string>,
    edgesFound = true,
  ): void {
    vi.stubGlobal('fetch', async (url: string) => {
      if (url.endsWith('/meta.json')) return new Response(JSON.stringify(metaJson))
      if (url.endsWith('/decls.jsonl')) {
        return new Response(chunked(declBody, 8), { headers: declHeaders })
      }
      if (url.endsWith('/stmt-edges.bin') && edgesFound) {
        return new Response(chunked(new Uint8Array(edgeBytes), 2))
      }
      return new Response(null, { status: 404 })
    })
  }

  async function load(): Promise<LoadProgress[]> {
    const seen: LoadProgress[] = []
    const parts = await fetchIndexParts('/index/test', (progress) => seen.push(progress))
    // The accounting must not have cost the caller any bytes.
    expect(parts.declText).toBe(declText)
    expect(seen.length).toBeGreaterThan(1)
    for (const progress of seen) {
      if (progress.total > 0) expect(progress.loaded).toBeLessThanOrEqual(progress.total)
    }
    return seen
  }

  it('prefers the size the exporter recorded over the header', async () => {
    // nginx serves this file gzipped on purpose, so the header is the
    // compressed size and the only reliable figure is the one written at export
    // time.  Both are present here, and the recorded one has to win.
    serve(
      { ...served, declBytes: declBody.byteLength },
      { 'content-length': '128', 'content-encoding': 'gzip' },
    )
    const seen = await load()
    expect(seen.some((p) => p.total === declBody.byteLength + edgeBytes)).toBe(true)
  })

  it('never reports more loaded than total for a compressed table', async () => {
    // An index exported before `declBytes` existed, served the way the Mathlib
    // one is: the header is a quarter of what arrives.  `load` checks the
    // invariant; what this pins is that the wrong number is not used at all.
    serve(served, {
      'content-length': String(declBody.byteLength >> 2),
      'content-encoding': 'gzip',
    })
    const seen = await load()
    for (const progress of seen.slice(0, -1)) expect(progress.total).toBe(0)
  })

  it('reports an indeterminate total when nothing says how big the table is', async () => {
    // A chunked response carries no length at all.  There is no honest number
    // to divide by, and `LoadProgress` documents 0 as "show a bar with no end".
    serve(served, {})
    const seen = await load()
    for (const progress of seen.slice(0, -1)) expect(progress.total).toBe(0)
  })

  it('still believes the header for an old index served uncompressed', async () => {
    // Without `Content-Encoding` the header does count the bytes that arrive,
    // and an index exported before the size was recorded still deserves a real
    // bar rather than a spinner.
    serve(served, { 'content-length': String(declBody.byteLength) })
    const seen = await load()
    expect(seen.some((p) => p.total === declBody.byteLength + edgeBytes)).toBe(true)
  })

  it('widens a total the download has already overtaken', async () => {
    // `meta.json` and `decls.jsonl` are two files, and a half-finished export or
    // a stale copy of one of them can leave the recorded size short.  The bar
    // may saturate; it may not run past its own end.
    serve({ ...served, declBytes: 8 }, {})
    const seen = await load()
    expect(seen.at(-1)!.loaded).toBe(declBody.byteLength + edgeBytes)
  })

  it('fills the bar even when an edge file is missing', async () => {
    // The edge bytes were counted into the total from `meta.json` before the
    // 404 was known, and a total that nothing will ever fill leaves the bar
    // parked short of the end until the build phase takes over.
    serve({ ...served, declBytes: declBody.byteLength }, {}, false)
    const seen = await load()
    expect(seen.at(-1)).toEqual({
      phase: 'fetch',
      loaded: declBody.byteLength,
      total: declBody.byteLength,
    })
  })
})

describe('repoOfModule', () => {
  it('groups the core libraries together', () => {
    expect(repoOfModule('Init.Data.Nat.Basic')).toBe('core')
    expect(repoOfModule('Lean.Expr')).toBe('core')
    expect(repoOfModule('Std.Data.HashMap')).toBe('core')
  })

  it('keeps other repositories separate', () => {
    expect(repoOfModule('Mathlib.Algebra.Group.Defs')).toBe('Mathlib')
    expect(repoOfModule('Batteries.Data.List')).toBe('Batteries')
  })
})