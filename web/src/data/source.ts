import type { Decl, DeclCode, DeclKind, Edge, EdgeKind, Graph, IndexMeta, NodeId } from './types'

/** Whether a neighbour should be listed at all; used by the repository filter. */
export type Accept = (id: NodeId) => boolean

/**
 * Everything the views need from an index.
 *
 * The static export is not the only conceivable backend — a server keeping a
 * Lean environment loaded could answer the same questions — so the views only
 * ever talk to this interface.
 */
export interface GraphSource {
  meta(): IndexMeta
  node(id: NodeId): Decl
  /**
   * The definitional dependencies of `id`, as edges labelled by where they came
   * from.
   *
   * This is the rule from `Trust/Deps.lean`: a declaration's statement always
   * counts, and its body counts only when the declaration carries data.  A
   * theorem therefore contributes its statement but never its proof term.
   */
  dependencyEdges(id: NodeId, limit?: number, accept?: Accept): { id: NodeId; kind: EdgeKind }[]
  /**
   * Up to `limit` neighbours in the given direction, optionally restricted to
   * those `accept` admits.
   *
   * The tree shows 50 rows at a time, but `Eq` has 43,823 dependents; building
   * the whole neighbour list to slice 50 off it dominated every expand.  The
   * filter is applied during the walk for the same reason — a filtered row must
   * cost what it displays, not what it could have displayed.
   */
  childEdges(
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    limit?: number,
    accept?: Accept,
  ): { id: NodeId; kind: EdgeKind }[]
  /**
   * Visit each child in the given direction; return false from `visit` to stop.
   *
   * The primitive the other neighbour queries are built from.  Counting a
   * closure means walking millions of edges, which is only affordable if the
   * walk allocates nothing per edge.
   */
  forEachChild(
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    visit: (target: NodeId, kind: EdgeKind) => boolean,
  ): void
  /** Declarations `id` definitionally depends on. */
  dependencies(id: NodeId): NodeId[]
  /** Declarations that depend on `id`, through statements or proofs. */
  dependents(id: NodeId): NodeId[]
  /**
   * How many neighbours `id` has in the given direction.
   *
   * Answered from the adjacency offsets without building the neighbour list, so
   * that a collapsed tree row costs nothing even when it has 30,000 children.
   */
  degree(id: NodeId, direction: 'dependencies' | 'dependents'): number
  /** Declarations whose name contains `query`, best matches first. */
  search(query: string, limit?: number): Decl[]
  /** The declaration with this exact name, if the index has one. */
  findByName(name: string): NodeId | null
  /**
   * The rendered declaration, or null if the index carries no code.
   *
   * Rendered code is sharded and fetched on demand: it is the largest part of
   * an index by far, and only the declaration on screen is ever needed.
   */
  code(id: NodeId): Promise<DeclCode | null>
  /** Repository names present in the index, derived from module roots. */
  repos(): string[]
  /** Which repository a declaration belongs to. */
  repoOf(id: NodeId): string
}

/**
 * The repository a module belongs to.
 *
 * An exported index covers a whole import closure, so a Mathlib export also
 * contains core and Batteries declarations.  The root component of the module
 * name is what distinguishes them, which is exactly what `DESIGN.md`'s "filter
 * definitions by repository" needs.
 */
export function repoOfModule(module: string): string {
  const root = module.split('.')[0]
  if (root === 'Init' || root === 'Lean' || root === 'Std') return 'core'
  return root || 'unknown'
}

/**
 * Parse `{"src":N,"tgt":M}` without going through `JSON.parse`.
 *
 * There are hundreds of thousands of these lines and the format is fixed by our
 * own exporter, so a digit scan is worth it; anything unexpected falls back to
 * the general parser.
 */
function parseEdgeLine(line: string): [number, number] | null {
  let i = 0
  let src = -1
  let tgt = -1
  while (i < line.length) {
    const c = line.charCodeAt(i)
    if (c >= 48 && c <= 57) {
      let value = 0
      while (i < line.length) {
        const d = line.charCodeAt(i)
        if (d < 48 || d > 57) break
        value = value * 10 + (d - 48)
        i++
      }
      if (src < 0) src = value
      else if (tgt < 0) tgt = value
      else return null
    } else {
      i++
    }
  }
  if (src < 0 || tgt < 0) return null
  return [src, tgt]
}

/** Parse a whole edge file into a flat `[src, tgt, src, tgt, ...]` buffer. */
function parseEdges(text: string): { pairs: Int32Array; count: number } {
  if (text.length === 0) return { pairs: new Int32Array(0), count: 0 }
  const lines = text.split('\n')
  const pairs = new Int32Array(2 * lines.length)
  let count = 0
  for (const line of lines) {
    if (line.length === 0) continue
    const parsed = parseEdgeLine(line)
    const [src, tgt] = parsed ?? [JSON.parse(line).src, JSON.parse(line).tgt]
    pairs[2 * count] = src
    pairs[2 * count + 1] = tgt
    count++
  }
  return { pairs, count }
}

/** A flat `(src, tgt)` edge buffer and how many pairs of it are live. */
interface EdgeChunk {
  pairs: Int32Array
  count: number
}

/** Compressed sparse row arrays, as they cross a thread boundary. */
export interface AdjacencyArrays {
  offsets: Int32Array
  targets: Int32Array
}

/** The declaration table's columns, as they cross a thread boundary. */
export interface DeclColumns {
  count: number
  nameBlob: string
  lowerBlob: string
  nameAt: Int32Array
  moduleList: string[]
  moduleOf: Int32Array
  moduleRepo: Int32Array
  repoList: string[]
  kindOf: Uint8Array
  flagOf: Uint8Array
  axioms: [NodeId, string[]][]
  slots: Int32Array
  mask: number
}

/**
 * A whole index in transferable form.
 *
 * Building one is the expensive part of a load — 313 ms of uninterrupted main
 * thread at Mathlib scale — so it happens in a worker and arrives here as typed
 * arrays, which transfer without being copied.
 */
export interface IndexPayload {
  metaText: string
  decls: DeclColumns
  stmt: AdjacencyArrays
  body: AdjacencyArrays
  reverse: AdjacencyArrays
}

/** The buffers in a payload, to hand to `postMessage` as its transfer list. */
export function payloadTransferables(payload: IndexPayload): ArrayBuffer[] {
  const { decls, stmt, body, reverse } = payload
  return [
    decls.nameAt,
    decls.moduleOf,
    decls.moduleRepo,
    decls.kindOf,
    decls.flagOf,
    decls.slots,
    stmt.offsets,
    stmt.targets,
    body.offsets,
    body.targets,
    reverse.offsets,
    reverse.targets,
  ].map((a) => a.buffer as ArrayBuffer)
}

/**
 * Compressed sparse row adjacency.
 *
 * A `Map<number, number[]>` would allocate one array per declaration; at
 * Mathlib scale that is hundreds of thousands of objects. Two typed arrays are
 * both smaller and faster to walk.
 */
class Adjacency {
  private constructor(
    private readonly offsets: Int32Array,
    private readonly targets: Int32Array,
  ) {}

  /**
   * Build from any number of edge buffers at once.
   *
   * The reverse adjacency spans both statement and body edges.  Concatenating
   * them into one buffer first cost a transient copy of the entire edge set —
   * 104 MB at Mathlib scale, on top of the adjacency being built from it — so
   * the chunks are counted and scattered in place instead.
   */
  static build(nodeCount: number, chunks: readonly EdgeChunk[], reverse: boolean): Adjacency {
    const offsets = new Int32Array(nodeCount + 1)
    let total = 0
    for (const { pairs, count } of chunks) {
      total += count
      for (let i = 0; i < count; i++) offsets[pairs[2 * i + (reverse ? 1 : 0)] + 1]++
    }
    for (let i = 0; i < nodeCount; i++) offsets[i + 1] += offsets[i]
    const cursor = Int32Array.from(offsets)
    const targets = new Int32Array(total)
    for (const { pairs, count } of chunks) {
      for (let i = 0; i < count; i++) {
        const from = pairs[2 * i + (reverse ? 1 : 0)]
        const to = pairs[2 * i + (reverse ? 0 : 1)]
        targets[cursor[from]++] = to
      }
    }
    return new Adjacency(offsets, targets)
  }

  /** Rebuild from arrays that were built elsewhere, typically in a worker. */
  static fromArrays(arrays: AdjacencyArrays): Adjacency {
    return new Adjacency(arrays.offsets, arrays.targets)
  }

  /** The backing arrays, for transferring to another thread. */
  arrays(): AdjacencyArrays {
    return { offsets: this.offsets, targets: this.targets }
  }

  get(id: number): NodeId[] {
    if (id < 0 || id + 1 >= this.offsets.length) return []
    const out: NodeId[] = []
    for (let i = this.offsets[id]; i < this.offsets[id + 1]; i++) out.push(this.targets[i])
    return out
  }

  /** Number of neighbours, without materialising them. */
  degree(id: number): number {
    if (id < 0 || id + 1 >= this.offsets.length) return 0
    return this.offsets[id + 1] - this.offsets[id]
  }

  /** Visit neighbours in order; return false from `visit` to stop early. */
  forEach(id: number, visit: (target: NodeId) => boolean): void {
    if (id < 0 || id + 1 >= this.offsets.length) return
    for (let i = this.offsets[id]; i < this.offsets[id + 1]; i++) {
      if (!visit(this.targets[i])) return
    }
  }
}

/** Declaration kinds, in the order their index is stored in. */
const KIND_NAMES: DeclKind[] = [
  'axiom',
  'def',
  'theorem',
  'opaque',
  'quot',
  'inductive',
  'ctor',
  'recursor',
]
const KIND_INDEX = new Map<string, number>(KIND_NAMES.map((k, i) => [k, i]))

const FLAG_IS_PROP = 1
const FLAG_IS_DATA = 2
const FLAG_USES_SORRY = 4

/** FNV-1a over a slice of a string, without materialising the slice. */
function hashRange(text: string, from: number, to: number): number {
  let h = 2166136261
  for (let i = from; i < to; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619)
  return h >>> 0
}

/**
 * The declaration table, stored by column rather than as objects.
 *
 * `JSON.parse` per line produced one object per declaration and a `Map` from
 * name to id; at Mathlib scale (226,368 declarations) that measured 47 MB and
 * 18 MB respectively, and the objects are almost all dead weight — a render
 * touches a few hundred of them.  Here the fields live in typed arrays and two
 * string blobs, `Decl` objects are built on demand by `decl`, and name lookup
 * uses an open-addressed table over the blob instead of a `Map`.
 *
 * Modules are interned: an index has hundreds of thousands of declarations but
 * only hundreds of distinct modules.
 */
class DeclTable {
  private constructor(
    readonly count: number,
    /** All names, separated by `\n`, which no Lean name contains. */
    private readonly nameBlob: string,
    /** `nameBlob` lower-cased; offsets coincide, so search can scan it whole. */
    private readonly lowerBlob: string,
    /** Start offset of each name, plus a terminator; name `i` ends at `[i+1]-1`. */
    private readonly nameAt: Int32Array,
    private readonly moduleList: string[],
    private readonly moduleOf: Int32Array,
    /** Repository of each distinct module, as an index into `repoList`. */
    private readonly moduleRepo: Int32Array,
    readonly repoList: string[],
    private readonly kindOf: Uint8Array,
    private readonly flagOf: Uint8Array,
    /** Only the declarations that actually carry axioms; a bulk export has none. */
    private readonly axiomsOf: Map<NodeId, string[]>,
    /** Open-addressed name index: slot holds `id + 1`, or 0 when empty. */
    private readonly slots: Int32Array,
    private readonly mask: number,
  ) {}

  /** Rebuild from columns that were built elsewhere, typically in a worker. */
  static fromColumns(c: DeclColumns): DeclTable {
    return new DeclTable(
      c.count,
      c.nameBlob,
      c.lowerBlob,
      c.nameAt,
      c.moduleList,
      c.moduleOf,
      c.moduleRepo,
      c.repoList,
      c.kindOf,
      c.flagOf,
      new Map(c.axioms),
      c.slots,
      c.mask,
    )
  }

  /** The columns, for transferring to another thread. */
  columns(): DeclColumns {
    return {
      count: this.count,
      nameBlob: this.nameBlob,
      lowerBlob: this.lowerBlob,
      nameAt: this.nameAt,
      moduleList: this.moduleList,
      moduleOf: this.moduleOf,
      moduleRepo: this.moduleRepo,
      repoList: this.repoList,
      kindOf: this.kindOf,
      flagOf: this.flagOf,
      axioms: [...this.axiomsOf],
      slots: this.slots,
      mask: this.mask,
    }
  }

  static parse(declText: string): DeclTable {
    const names: string[] = []
    const moduleList: string[] = []
    const moduleIndex = new Map<string, number>()
    const moduleOfList: number[] = []
    const kinds: number[] = []
    const flags: number[] = []
    const axiomsOf = new Map<NodeId, string[]>()

    // Walked with `indexOf` rather than `split('\n')`: the split materialises a
    // substring per declaration up front, all of which stay alive until the
    // whole file has been parsed.
    let pos = 0
    while (pos < declText.length) {
      let end = declText.indexOf('\n', pos)
      if (end < 0) end = declText.length
      if (end > pos) {
        const parsed: Decl = JSON.parse(declText.slice(pos, end))
        const id = names.length
        names.push(parsed.name)
        let module = moduleIndex.get(parsed.module)
        if (module === undefined) {
          module = moduleList.length
          moduleList.push(parsed.module)
          moduleIndex.set(parsed.module, module)
        }
        moduleOfList.push(module)
        kinds.push(KIND_INDEX.get(parsed.kind) ?? 0)
        flags.push(
          (parsed.isProp ? FLAG_IS_PROP : 0) |
            (parsed.isData ? FLAG_IS_DATA : 0) |
            (parsed.usesSorry ? FLAG_USES_SORRY : 0),
        )
        if (parsed.axioms && parsed.axioms.length > 0) axiomsOf.set(id, parsed.axioms)
      }
      pos = end + 1
    }

    const count = names.length
    const nameAt = new Int32Array(count + 1)
    let offset = 0
    for (let i = 0; i < count; i++) {
      nameAt[i] = offset
      offset += names[i].length + 1
    }
    nameAt[count] = offset
    const nameBlob = names.join('\n')
    // Lower-casing is done on the blob so that search can scan it in one native
    // `indexOf` rather than per name.  A few code points change length when
    // lower-cased; if that ever happens the offsets no longer line up, so fall
    // back to a blob that is only used for exact comparisons.
    let lowerBlob = nameBlob.toLowerCase()
    if (lowerBlob.length !== nameBlob.length) {
      // Pad or clip each name back to its original width so that the offsets in
      // `nameAt` keep addressing both blobs.
      lowerBlob = names
        .map((n) => {
          const lower = n.toLowerCase()
          return lower.length === n.length ? lower : lower.slice(0, n.length).padEnd(n.length, ' ')
        })
        .join('\n')
    }

    const repoList: string[] = []
    const repoIndex = new Map<string, number>()
    const moduleRepo = new Int32Array(moduleList.length)
    for (let i = 0; i < moduleList.length; i++) {
      const repo = repoOfModule(moduleList[i])
      let index = repoIndex.get(repo)
      if (index === undefined) {
        index = repoList.length
        repoList.push(repo)
        repoIndex.set(repo, index)
      }
      moduleRepo[i] = index
    }
    // `repos()` is displayed sorted; remap rather than sort the array in place,
    // which would invalidate the indices already written into `moduleRepo`.
    // Ordered by code unit, as a bare `.sort()` on the names would be, so that
    // `Mathlib` still precedes `core`.
    const order = repoList
      .map((_, i) => i)
      .sort((a, b) => (repoList[a] < repoList[b] ? -1 : repoList[a] > repoList[b] ? 1 : 0))
    const rank = new Int32Array(repoList.length)
    order.forEach((original, position) => (rank[original] = position))
    for (let i = 0; i < moduleRepo.length; i++) moduleRepo[i] = rank[moduleRepo[i]]

    let size = 1
    while (size < Math.max(2, count * 2)) size <<= 1
    const slots = new Int32Array(size)
    const mask = size - 1
    for (let id = 0; id < count; id++) {
      let slot = hashRange(lowerBlob, nameAt[id], nameAt[id + 1] - 1) & mask
      while (slots[slot] !== 0) slot = (slot + 1) & mask
      slots[slot] = id + 1
    }

    return new DeclTable(
      count,
      nameBlob,
      lowerBlob,
      nameAt,
      moduleList,
      Int32Array.from(moduleOfList),
      moduleRepo,
      order.map((i) => repoList[i]),
      Uint8Array.from(kinds),
      Uint8Array.from(flags),
      axiomsOf,
      slots,
      mask,
    )
  }

  private valid(id: NodeId): boolean {
    return Number.isInteger(id) && id >= 0 && id < this.count
  }

  name(id: NodeId): string {
    return this.nameBlob.slice(this.nameAt[id], this.nameAt[id + 1] - 1)
  }

  module(id: NodeId): string {
    return this.moduleList[this.moduleOf[id]]
  }

  isData(id: NodeId): boolean {
    return this.valid(id) && (this.flagOf[id] & FLAG_IS_DATA) !== 0
  }

  repoOf(id: NodeId): string {
    if (!this.valid(id)) return 'unknown'
    return this.repoList[this.moduleRepo[this.moduleOf[id]]] ?? 'unknown'
  }

  /** A `Decl` object, built on demand — only what is on screen is ever built. */
  decl(id: NodeId): Decl {
    if (!this.valid(id)) return undefined as unknown as Decl
    const flags = this.flagOf[id]
    const out: Decl = {
      id,
      name: this.name(id),
      module: this.module(id),
      kind: KIND_NAMES[this.kindOf[id]],
      isProp: (flags & FLAG_IS_PROP) !== 0,
      isData: (flags & FLAG_IS_DATA) !== 0,
    }
    if ((flags & FLAG_USES_SORRY) !== 0) out.usesSorry = true
    const axioms = this.axiomsOf.get(id)
    if (axioms) out.axioms = axioms
    return out
  }

  /** The declaration owning a given offset into the name blob. */
  private idAtOffset(offset: number): NodeId {
    let lo = 0
    let hi = this.count - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (this.nameAt[mid] <= offset) lo = mid
      else hi = mid - 1
    }
    return lo
  }

  /**
   * Exact lookup through the open-addressed table.
   *
   * Slots are keyed by the lower-cased hash so that both the case-sensitive
   * lookup `findByName` needs and the case-insensitive one `search` needs can
   * walk the same probe chain.
   */
  private probe(needle: string, caseInsensitive: boolean): NodeId | null {
    if (this.count === 0) return null
    const blob = caseInsensitive ? this.lowerBlob : this.nameBlob
    const lower = caseInsensitive ? needle : needle.toLowerCase()
    let slot = hashRange(lower, 0, lower.length) & this.mask
    while (this.slots[slot] !== 0) {
      const id = this.slots[slot] - 1
      const start = this.nameAt[id]
      if (this.nameAt[id + 1] - 1 - start === needle.length && blob.startsWith(needle, start)) {
        return id
      }
      slot = (slot + 1) & this.mask
    }
    return null
  }

  findByName(name: string): NodeId | null {
    return this.probe(name, false)
  }

  search(query: string, limit: number): Decl[] {
    const needle = query.trim().toLowerCase()
    if (needle.length === 0 || needle.includes('\n')) return []

    // The exact match is looked up directly.  Scanning for it would mean
    // reading the whole blob every time, since a better match can always lie
    // further along; this way the scan may stop as soon as the other two
    // buckets are full.
    const exact: NodeId[] = []
    const seen = new Set<NodeId>()
    const direct = this.probe(needle, true)
    if (direct !== null) {
      exact.push(direct)
      seen.add(direct)
    }

    const prefix: NodeId[] = []
    const infix: NodeId[] = []
    let pos = 0
    while (prefix.length < limit || infix.length < limit) {
      const hit = this.lowerBlob.indexOf(needle, pos)
      if (hit < 0) break
      const id = this.idAtOffset(hit)
      const start = this.nameAt[id]
      const end = this.nameAt[id + 1] - 1
      // One name, one result.  A name can contain the needle many times over —
      // `a` occurs three times in `banana` — and scanning the blob finds every
      // one of them; listing a declaration once per occurrence put duplicate
      // keys in the results, which React renders unpredictably.  Skipping to
      // the end of the name both deduplicates and saves the rescan.
      pos = end + 1
      if (seen.has(id)) continue
      seen.add(id)
      // A hit running past the name's end spans the separator and matches
      // neither name.
      if (hit + needle.length > end) continue
      if (hit !== start) {
        if (infix.length < limit) infix.push(id)
      } else if (end - start === needle.length) {
        exact.push(id)
      } else if (prefix.length < limit) {
        prefix.push(id)
      }
    }
    return [...exact, ...prefix, ...infix].slice(0, limit).map((id) => this.decl(id))
  }
}

/**
 * How far a load has got.
 *
 * An index is tens of megabytes, so a load is long enough that the page has to
 * account for itself while it runs.  `total` is 0 when the size could not be
 * determined, which the view shows as an indeterminate bar.
 */
export interface LoadProgress {
  phase: 'fetch' | 'build'
  loaded: number
  total: number
}

/** Read a response body to the end, reporting each chunk as it arrives. */
async function readBody(response: Response, onChunk: (bytes: number) => void): Promise<Uint8Array> {
  if (!response.body) {
    const whole = new Uint8Array(await response.arrayBuffer())
    onChunk(whole.byteLength)
    return whole
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    size += value.byteLength
    onChunk(value.byteLength)
  }
  const out = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) {
    out.set(chunk, at)
    at += chunk.byteLength
  }
  return out
}

/**
 * Fetch the raw files an index is made of.
 *
 * Shared by the worker and the inline fallback so that both read exactly the
 * same bytes.
 */
export async function fetchIndexParts(
  base: string,
  onProgress?: (progress: LoadProgress) => void,
): Promise<{
  metaText: string
  declText: string
  stmtPairs: Int32Array
  bodyPairs: Int32Array
  meta: IndexMeta
}> {
  const metaText = await fetch(`${base}/meta.json`).then((r) => r.text())
  const meta: IndexMeta = JSON.parse(metaText)

  // An edge is exactly eight bytes, so the edge files' sizes are known from
  // `meta.json` before any of them has arrived; only the declaration table has
  // to be asked for its length.
  const declResponse = await fetch(`${base}/decls.jsonl`)
  const declBytes = Number(declResponse.headers.get('content-length') ?? 0)
  // Body edges are optional: `trust export` only writes them with --with-bodies.
  const bodyEdgeBytes = meta.hasBodyEdges ? meta.bodyEdgeCount * 8 : 0
  const total = declBytes + meta.stmtEdgeCount * 8 + bodyEdgeBytes

  let loaded = 0
  let reported = 0
  const report = (bytes: number) => {
    loaded += bytes
    // One message per chunk would be thousands of them; a percent is plenty,
    // and the view cannot show more resolution than that anyway.
    if (onProgress && (total <= 0 || loaded - reported >= total / 100)) {
      reported = loaded
      onProgress({ phase: 'fetch', loaded, total })
    }
  }

  // Edges arrive as raw int32 pairs and are used as-is.  Parsing them from
  // JSON meant holding tens of megabytes of text and over a million transient
  // line strings, which ran browsers out of memory.
  const asPairs = async (url: string): Promise<Int32Array> => {
    const response = await fetch(url)
    if (!response.ok) return new Int32Array(0)
    const bytes = await readBody(response, report)
    return new Int32Array(bytes.buffer, bytes.byteOffset, bytes.byteLength >> 2)
  }
  const [declBody, stmtPairs, bodyPairs] = await Promise.all([
    readBody(declResponse, report),
    asPairs(`${base}/stmt-edges.bin`),
    meta.hasBodyEdges ? asPairs(`${base}/body-edges.bin`) : Promise.resolve(new Int32Array(0)),
  ])
  onProgress?.({ phase: 'fetch', loaded, total })
  return { metaText, declText: new TextDecoder().decode(declBody), stmtPairs, bodyPairs, meta }
}

/**
 * Body edges that start at a data-carrying declaration.
 *
 * A proof is a leaf: `Trust/Deps.lean` never unfolds one, so what a proof term
 * happens to mention is not a dependency of the theorem — the statement is the
 * whole of what a theorem rests on.  The forward walk already honoured that,
 * but the reverse relation was built over every body edge, so a theorem came
 * out as a *dependent* of everything its proof touched.  Dropping them here
 * makes both directions agree, and takes 89% of the body edges with them.
 */
function bodyEdgesFromData(pairs: Int32Array, table: DeclTable): EdgeChunk {
  const total = pairs.length >> 1
  let count = 0
  for (let i = 0; i < total; i++) if (table.isData(pairs[2 * i])) count++
  if (count === total) return { pairs, count }
  // Sized exactly, and in a second pass: an over-allocated buffer here is as
  // large as the edge set it is filtering, which is what it is meant to shrink.
  const kept = new Int32Array(2 * count)
  let at = 0
  for (let i = 0; i < total; i++) {
    if (!table.isData(pairs[2 * i])) continue
    kept[at++] = pairs[2 * i]
    kept[at++] = pairs[2 * i + 1]
  }
  return { pairs: kept, count }
}

/** Parse the declarations and build all three adjacencies. */
export function buildIndexPayload(
  metaText: string,
  declText: string,
  stmtPairs: Int32Array,
  bodyPairs: Int32Array,
): IndexPayload {
  const table = DeclTable.parse(declText)
  const stmt: EdgeChunk = { pairs: stmtPairs, count: stmtPairs.length >> 1 }
  const body: EdgeChunk = bodyEdgesFromData(bodyPairs, table)
  return {
    metaText,
    decls: table.columns(),
    stmt: Adjacency.build(table.count, [stmt], false).arrays(),
    body: Adjacency.build(table.count, [body], false).arrays(),
    // Dependents are computed over both kinds: a theorem that uses a declaration
    // only in its proof still depends on it.
    reverse: Adjacency.build(table.count, [stmt, body], true).arrays(),
  }
}

/** What the index worker sends back while and after it works. */
export type WorkerMessage =
  | { type: 'progress'; progress: LoadProgress }
  | { type: 'done'; payload: IndexPayload; hasCode: boolean }
  | { type: 'error'; error: string }

/** Run one index build in a dedicated worker, then let the worker go. */
function buildIndexInWorker(
  base: string,
  onProgress?: (progress: LoadProgress) => void,
): Promise<{ payload: IndexPayload; hasCode: boolean }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./indexWorker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
      const message = event.data
      if (message.type === 'progress') {
        onProgress?.(message.progress)
        return
      }
      worker.terminate()
      if (message.type === 'done') resolve({ payload: message.payload, hasCode: message.hasCode })
      else reject(new Error(message.error))
    }
    worker.onerror = (event) => {
      worker.terminate()
      reject(new Error(event.message || 'index worker failed to start'))
    }
    worker.postMessage({ base })
  })
}

/** A `GraphSource` backed by the static JSONL index written by `trust export`. */
export class StaticIndexSource implements GraphSource {
  /** Base URL for lazily fetched code shards; unset when built from text. */
  private codeBase: string | null = null
  private readonly codeShards = new Map<number, Promise<Map<NodeId, DeclCode>>>()

  private constructor(
    private readonly indexMeta: IndexMeta,
    private readonly table: DeclTable,
    private readonly statementForward: Adjacency,
    private readonly bodyForward: Adjacency,
    private readonly reverse: Adjacency,
  ) {}

  /**
   * Load an index, building it off the main thread when that is possible.
   *
   * Parsing the declarations and building the three adjacencies is one
   * uninterruptible task — 313 ms at Mathlib scale — which is long enough to
   * drop every frame and every click made while the page is coming up.  In the
   * worker it costs the main thread only the arrival of the finished arrays,
   * which transfer rather than copy.  A browser without workers, or a worker
   * that fails to start, still gets the inline path.
   */
  static async load(
    baseUrl: string,
    repo: string,
    onProgress?: (progress: LoadProgress) => void,
  ): Promise<StaticIndexSource> {
    const base = `${baseUrl}/${repo}`
    if (typeof Worker !== 'undefined') {
      try {
        const { payload, hasCode } = await buildIndexInWorker(base, onProgress)
        const source = StaticIndexSource.fromPayload(payload)
        if (hasCode) source.codeBase = base
        return source
      } catch {
        // Fall through and build inline.
      }
    }
    const parts = await fetchIndexParts(base, onProgress)
    onProgress?.({ phase: 'build', loaded: 0, total: 0 })
    const source = StaticIndexSource.fromParts(
      parts.metaText,
      parts.declText,
      parts.stmtPairs,
      parts.bodyPairs,
    )
    if (parts.meta.hasCode) source.codeBase = base
    return source
  }

  /** Wrap an already-built index; the arrays are adopted, not copied. */
  static fromPayload(payload: IndexPayload): StaticIndexSource {
    return new StaticIndexSource(
      JSON.parse(payload.metaText),
      DeclTable.fromColumns(payload.decls),
      Adjacency.fromArrays(payload.stmt),
      Adjacency.fromArrays(payload.body),
      Adjacency.fromArrays(payload.reverse),
    )
  }

  /** Build a source from a declaration table and flat `(src, tgt)` edge pairs. */
  static fromParts(
    metaText: string,
    declText: string,
    stmtPairs: Int32Array,
    bodyPairs: Int32Array,
  ): StaticIndexSource {
    return StaticIndexSource.fromPayload(
      buildIndexPayload(metaText, declText, stmtPairs, bodyPairs),
    )
  }

  /**
   * Build a source from JSONL edge text.
   *
   * Kept for fixtures and tests, where readable edges are worth more than the
   * memory they cost.  The exporter and `load` use the binary form.
   */
  static fromText(
    metaText: string,
    declText: string,
    stmtText: string,
    bodyText = '',
  ): StaticIndexSource {
    const stmt = parseEdges(stmtText)
    const body = parseEdges(bodyText)
    return StaticIndexSource.fromParts(
      metaText,
      declText,
      stmt.pairs.subarray(0, 2 * stmt.count),
      body.pairs.subarray(0, 2 * body.count),
    )
  }

  meta(): IndexMeta {
    return this.indexMeta
  }

  node(id: NodeId): Decl {
    return this.table.decl(id)
  }

  forEachChild(
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    visit: (target: NodeId, kind: EdgeKind) => boolean,
  ): void {
    if (direction === 'dependents') {
      this.reverse.forEach(id, (target) => visit(target, 'statement'))
      return
    }
    const isData = this.table.isData(id)
    // The statement targets are only remembered when the body is going to be
    // walked as well; for a proof there is nothing to deduplicate against.
    const seen = isData ? new Set<NodeId>() : null
    let carryOn = true
    this.statementForward.forEach(id, (target) => {
      seen?.add(target)
      carryOn = visit(target, 'statement')
      return carryOn
    })
    // Only data-carrying declarations unfold through their body; a proof is a leaf.
    if (!carryOn || !isData) return
    this.bodyForward.forEach(id, (target) => {
      // A name used in both the statement and the body is one dependency, not two.
      if (seen!.has(target)) return true
      carryOn = visit(target, 'body')
      return carryOn
    })
  }

  dependencyEdges(id: NodeId, limit = Infinity, accept?: Accept): { id: NodeId; kind: EdgeKind }[] {
    return this.childEdges(id, 'dependencies', limit, accept)
  }

  childEdges(
    id: NodeId,
    direction: 'dependencies' | 'dependents',
    limit = Infinity,
    accept?: Accept,
  ) {
    const out: { id: NodeId; kind: EdgeKind }[] = []
    if (limit <= 0) return out
    this.forEachChild(id, direction, (target, kind) => {
      if (accept && !accept(target)) return true
      out.push({ id: target, kind })
      return out.length < limit
    })
    return out
  }

  dependencies(id: NodeId): NodeId[] {
    return this.dependencyEdges(id).map((e) => e.id)
  }

  dependents(id: NodeId): NodeId[] {
    return this.reverse.get(id)
  }

  degree(id: NodeId, direction: 'dependencies' | 'dependents'): number {
    // Dependents come straight from the adjacency offsets.
    if (direction === 'dependents') return this.reverse.degree(id)
    // Dependencies have to be walked: adding the statement and body degrees
    // counts a name used in both of them twice, so the number on a collapsed
    // row disagreed with the number of rows it opened to.  Out-degrees are
    // small — it is in-degrees that reach the hundreds of thousands — so the
    // walk is cheap even with a row per declaration on screen.
    let count = 0
    this.forEachChild(id, 'dependencies', () => {
      count++
      return true
    })
    return count
  }

  repos(): string[] {
    return this.table.repoList
  }

  findByName(name: string): NodeId | null {
    return this.table.findByName(name)
  }

  async code(id: NodeId): Promise<DeclCode | null> {
    if (this.codeBase === null) return null
    const shardSize = this.indexMeta.codeShardSize ?? 2000
    const shard = Math.floor(id / shardSize)
    let pending = this.codeShards.get(shard)
    if (!pending) {
      // Each shard holds ~2000 rendered declarations; caching every shard a user
      // browses through would retain the whole 25 MB code export.
      if (this.codeShards.size >= 4) {
        this.codeShards.delete(this.codeShards.keys().next().value!)
      }
      const base = this.codeBase
      pending = fetch(`${base}/code/${shard}.jsonl`)
        .then((response) => (response.ok ? response.text() : ''))
        .then((text) => {
          const entries = new Map<NodeId, DeclCode>()
          for (const line of text.split('\n')) {
            if (line.length === 0) continue
            const entry: DeclCode = JSON.parse(line)
            entries.set(entry.id, entry)
          }
          return entries
        })
        .catch(() => new Map<NodeId, DeclCode>())
      this.codeShards.set(shard, pending)
    }
    return (await pending).get(id) ?? null
  }

  repoOf(id: NodeId): string {
    return this.table.repoOf(id)
  }

  search(query: string, limit = 50): Decl[] {
    return this.table.search(query, limit)
  }
}

/**
 * The same index with some declarations left out.
 *
 * Both the repository filter and the reader's hidden list are the same
 * operation — drop these children, everywhere — so both go through here rather
 * than each view growing its own predicate.  The root is never dropped: a view
 * has to be looking at something, and filtering away the thing you navigated to
 * would leave an empty page with no way back.
 */
export function filterSource(base: GraphSource, accept: Accept | null): GraphSource {
  if (!accept) return base

  const forEachChild: GraphSource['forEachChild'] = (id, direction, visit) => {
    base.forEachChild(id, direction, (target, kind) => (accept(target) ? visit(target, kind) : true))
  }

  const childEdges: GraphSource['childEdges'] = (id, direction, limit = Infinity, also) => {
    const out: { id: NodeId; kind: EdgeKind }[] = []
    if (limit <= 0) return out
    forEachChild(id, direction, (target, kind) => {
      if (also && !also(target)) return true
      out.push({ id: target, kind })
      return out.length < limit
    })
    return out
  }

  return {
    meta: () => base.meta(),
    node: (id) => base.node(id),
    forEachChild,
    childEdges,
    dependencyEdges: (id, limit, also) => childEdges(id, 'dependencies', limit, also),
    dependencies: (id) => childEdges(id, 'dependencies').map((edge) => edge.id),
    dependents: (id) => childEdges(id, 'dependents').map((edge) => edge.id),
    degree: (id, direction) => {
      let count = 0
      forEachChild(id, direction, () => {
        count++
        return true
      })
      return count
    },
    search: (query, limit) => base.search(query, limit),
    findByName: (name) => base.findByName(name),
    code: (id) => base.code(id),
    repos: () => base.repos(),
    repoOf: (id) => base.repoOf(id),
  }
}

/** The true size of a closure, which the rendered graph may only be part of. */
export interface ClosureSize {
  nodes: number
  edges: number
  /** False when the walk hit `maxWork`, making the counts lower bounds. */
  complete: boolean
}

/**
 * Count the whole closure, without building it.
 *
 * `closure` stops at a node and edge budget, because a few hundred elements is
 * all the graph view can lay out.  Reporting those budgets as the size of the
 * closure told the user the wrong thing entirely — `Eq` reads as 150 nodes when
 * essentially the whole library rests on it.  This walks the same traversal to
 * the end and only counts, so the caption can state what is really there.
 *
 * `maxWork` is a stop so that a pathological root cannot hang the page; it is
 * set above the edge count of a Mathlib-sized index, so in practice the answer
 * is exact and `complete` is true.
 */
/** Edges counted between yields, chosen to keep each slice a few milliseconds. */
const COUNT_CHUNK = 250_000

/** The counting walk, as a generator so it can be driven with or without yielding. */
function* closureCounter(
  source: GraphSource,
  root: NodeId,
  maxDepth: number,
  direction: 'dependencies' | 'dependents',
  maxWork: number,
): Generator<void, ClosureSize, void> {
  const seen = new Set<NodeId>([root])
  let edges = 0
  let complete = true
  let sinceYield = 0
  let frontier: NodeId[] = [root]

  outer: for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: NodeId[] = []
    for (const id of frontier) {
      source.forEachChild(id, direction, (target) => {
        edges++
        sinceYield++
        if (edges >= maxWork) {
          complete = false
          return false
        }
        if (!seen.has(target)) {
          seen.add(target)
          next.push(target)
        }
        return true
      })
      if (!complete) break outer
      // Yielding happens between nodes, so one declaration with 408,544
      // dependents is still a single slice; that is a few milliseconds, which
      // is short enough not to be felt.
      if (sinceYield >= COUNT_CHUNK) {
        sinceYield = 0
        yield
      }
    }
    frontier = next
  }
  return { nodes: seen.size, edges, complete }
}

export function closureSize(
  source: GraphSource,
  root: NodeId,
  maxDepth: number,
  direction: 'dependencies' | 'dependents' = 'dependencies',
  maxWork = 25_000_000,
): ClosureSize {
  const steps = closureCounter(source, root, maxDepth, direction, maxWork)
  let step = steps.next()
  while (!step.done) step = steps.next()
  return step.value
}

/** Hand the main thread back without waiting out `setTimeout`'s clamp. */
function yieldToBrowser(): Promise<void> {
  const scheduler = (globalThis as { scheduler?: { yield?: () => Promise<void> } }).scheduler
  if (scheduler?.yield) return scheduler.yield()
  return new Promise((resolve) => {
    const channel = new MessageChannel()
    channel.port1.onmessage = () => {
      channel.port1.close()
      resolve()
    }
    channel.port2.postMessage(null)
  })
}

/**
 * Start counting, finishing straight away when the closure is small.
 *
 * Most closures are a few hundred edges and counting them is free, so they
 * answer synchronously and the caption can be rendered from the result with no
 * second pass.  The ones that are not — `Eq`'s dependents are 14,478,339 edges,
 * 377 ms in one go — report `done: false`, and `rest` finishes them in slices so
 * that dragging the depth slider neither stalls nor pays for the depths passed
 * through on the way.
 *
 * `rest` resolves to null when `cancelled` turns true.
 */
export function beginClosureSize(
  source: GraphSource,
  root: NodeId,
  maxDepth: number,
  direction: 'dependencies' | 'dependents',
  maxWork = 25_000_000,
):
  | { done: true; size: ClosureSize }
  | { done: false; rest: (cancelled: () => boolean) => Promise<ClosureSize | null> } {
  const steps = closureCounter(source, root, maxDepth, direction, maxWork)
  const first = steps.next()
  if (first.done) return { done: true, size: first.value }
  return {
    done: false,
    rest: async (cancelled) => {
      for (;;) {
        if (cancelled()) return null
        await yieldToBrowser()
        if (cancelled()) return null
        const step = steps.next()
        if (step.done) return step.value
      }
    },
  }
}

/**
 * Breadth-first expansion of the definitional closure, bounded by depth.
 *
 * The index stores only the direct relation — per-declaration transitive
 * closures would be quadratic in the size of the library — so the closure the
 * graph view renders is computed here, on demand.
 */
export function closure(
  source: GraphSource,
  root: NodeId,
  maxDepth: number,
  direction: 'dependencies' | 'dependents' = 'dependencies',
  maxNodes = 150,
  maxEdges = 400,
): Graph {
  const seen = new Set<NodeId>([root])
  const edges: Edge[] = []
  let frontier: NodeId[] = [root]
  let truncated = false

  // The budget is enforced per edge, not per node.  A single declaration can
  // have tens of thousands of dependents — `Eq` has 43,823 — so checking only
  // between nodes lets one step overshoot the budget by two orders of
  // magnitude, which is far more than the graph view can lay out or render.
  //
  // The remaining edge budget is also passed down as a limit, so that a step
  // never materialises more neighbours than the traversal could possibly keep.
  outer: for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: NodeId[] = []
    for (const id of frontier) {
      const remaining = maxEdges - edges.length + 1
      for (const { id: target, kind } of source.childEdges(id, direction, remaining)) {
        if (edges.length >= maxEdges || (!seen.has(target) && seen.size >= maxNodes)) {
          truncated = true
          break outer
        }
        const [src, tgt] = direction === 'dependencies' ? [id, target] : [target, id]
        edges.push({ src, tgt, kind })
        if (!seen.has(target)) {
          seen.add(target)
          next.push(target)
        }
      }
    }
    frontier = next
  }

  const nodes = [...seen].map((id) => source.node(id))
  const kept = new Set(nodes.map((n) => n.id))
  return { root, nodes, edges: edges.filter((e) => kept.has(e.src) && kept.has(e.tgt)), truncated }
}