import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { StaticIndexSource, filterSource, type Accept, type GraphSource, type LoadProgress } from './data/source'
import type { Decl, DeclCode, NodeId } from './data/types'
import { CodeView } from './components/CodeView'
import { DepsTree, type Direction } from './components/DepsTree'
import { GraphView } from './components/GraphView'
import { ExpandedGraph } from './components/ExpandedGraph'
import { KindBadge } from './components/KindBadge'
import { MarksPanel, type MarksEdit } from './components/MarksPanel'
import { indexMarks, loadMarks, saveMarks, emptyMarks, type MarksIndex } from './data/marks'
import { pathTo, trustedCutSource } from './data/trustedMode'
import { WhoTrusts } from './components/WhoTrusts'
import {
  SERVER,
  currentIdentity,
  trustList,
  trustedHashes,
  type Identity,
} from './data/certificates'
import { defaultHidden, loadHidden, saveHidden, type HiddenConfig } from './data/hidden'

const INDEX_BASE = '/index'

/** Initial view state, so that a particular declaration can be linked to. */
const params = new URLSearchParams(window.location.search)
/**
 * Which exported index to read.
 *
 * `trust export --repo <name>` writes one directory per repository, so several
 * can sit side by side under `web/public/index` and `?repo=` chooses between
 * them — `?repo=core` for the Lean core export, the default for Mathlib.
 */
const INDEX_REPO = params.get('repo') ?? 'mathlib'
const INITIAL_DECL = params.get('decl') ?? 'Nat.gcd'
const INITIAL_DIRECTION: Direction = params.get('dir') === 'dependents' ? 'dependents' : 'dependencies'
const INITIAL_DEPTH = Number(params.get('depth') ?? 2)

/** How many previous positions the back button can walk through. */
const HISTORY_LIMIT = 200

/** Byte counts, at the resolution a progress line can usefully show. */
function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} kB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function App() {
  const [source, setSource] = useState<GraphSource | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState(INITIAL_DECL)
  const [root, setRoot] = useState<NodeId | null>(null)
  /** Highlighted node.  A graph click moves this; only a focus moves `root`. */
  const [selected, setSelected] = useState<NodeId | null>(null)
  /**
   * Whether the selection came from a click rather than from navigating.
   *
   * Focusing sets the selection to the new root, and dimming the graph the
   * moment it appears would answer a question nobody asked; the dimming is a
   * response to picking a node, so it only follows a pick.
   */
  const [picked, setPicked] = useState(false)
  /** Roots visited before this one, most recent last. */
  const [past, setPast] = useState<NodeId[]>([])
  /**
   * On by default: the question `trust` exists to answer is what a statement
   * still rests on that you have *not* accepted, so tracing past your own
   * judgements is the exception rather than the rule.
   */
  const [upToTrusted, setUpToTrusted] = useState(true)
  /** The full-screen graph, off unless asked for and remembered in the URL. */
  const [expanded, setExpanded] = useState(params.get('graph') === 'expanded')
  const [direction, setDirection] = useState<Direction>(INITIAL_DIRECTION)
  const [depth, setDepth] = useState(INITIAL_DEPTH)
  const [repoFilter, setRepoFilter] = useState<Set<string>>(new Set())
  const [code, setCode] = useState<DeclCode | null>(null)
  const [progress, setProgress] = useState<LoadProgress | null>(null)
  const [marks, setMarks] = useState<MarksIndex>(() => indexMarks(emptyMarks, false))
  /** Personal, not shared: kept in this browser rather than in the marks file. */
  const [hidden, setHidden] = useState<HiddenConfig>(() =>
    typeof window === 'undefined' ? defaultHidden : loadHidden(),
  )
  /** Who you are on the certificate server, and whose certificates you count. */
  const [identity, setIdentity] = useState<Identity | null>(null)
  const [following, setFollowing] = useState<Set<string>>(new Set())
  /** Hashes vouched for by the people you follow. */
  const [federated, setFederated] = useState<Set<string>>(new Set())

  // Loading an index is tens of megabytes and one worker.  `StrictMode` runs
  // effects twice in development, which downloaded and built the whole thing
  // twice over; the guard makes the load happen once per page instead.
  const loadStarted = useRef(false)

  useEffect(() => {
    if (loadStarted.current) return
    loadStarted.current = true
    // Marks are small and independent of the index, so a failure to load them
    // must not stop the graph from coming up.
    loadMarks(`${INDEX_BASE}/${INDEX_REPO}`)
      .then(setMarks)
      .catch(() => {})
    StaticIndexSource.load(INDEX_BASE, INDEX_REPO, setProgress)
      .then((loaded) => {
        setSource(loaded)
        // Prefer an exact name: `?decl=Eq` must land on `Eq`, not on some
        // longer declaration that merely contains it.
        const initial = loaded.findByName(INITIAL_DECL) ?? loaded.search(INITIAL_DECL, 1)[0]?.id
        if (initial !== undefined && initial !== null) {
          setRoot(initial)
          setSelected(initial)
        }
      })
      .catch((e) => setError(String(e)))
  }, [])

  /**
   * Refresh who you are, whom you follow, and what they vouch for.
   *
   * All three fail soft: the certificate server being absent or down leaves the
   * index perfectly usable, which is the point of it being a static export.
   */
  const refreshFederation = useCallback(async () => {
    if (!SERVER) return
    const me = await currentIdentity()
    setIdentity(me)
    if (!me) {
      setFollowing(new Set())
      setFederated(new Set())
      return
    }
    const [list, hashes] = await Promise.all([
      trustList(),
      trustedHashes(source?.meta().hasher ?? 'semantic-v1'),
    ])
    setFollowing(new Set(list.map((entry) => entry.login)))
    setFederated(hashes)
  }, [source])

  useEffect(() => {
    void refreshFederation()
  }, [refreshFederation])

  // Keep the address bar in step with the view, without adding history entries.
  useEffect(() => {
    if (!source || root === null) return
    // `repo` is carried through so that a reload, or a shared link, stays on the
    // index the view is actually showing.
    const next = new URLSearchParams({
      repo: INDEX_REPO,
      decl: source.node(root).name,
      dir: direction,
      depth: String(depth),
    })
    if (expanded) next.set('graph', 'expanded')
    window.history.replaceState(null, '', `?${next}`)
  }, [source, root, direction, depth, expanded])

  // Code shards are fetched lazily, so a stale response must not overwrite a
  // newer selection.
  useEffect(() => {
    if (!source || root === null) {
      setCode(null)
      return
    }
    let current = true
    setCode(null)
    source.code(root).then((loaded) => {
      if (current) setCode(loaded)
    })
    return () => {
      current = false
    }
  }, [source, root])

  const results = useMemo(() => (source ? source.search(query, 40) : []), [source, query])

  const hiddenNames = useMemo(() => new Set(hidden.names), [hidden.names])
  const isHidden = useCallback(
    (id: NodeId) => (source ? hiddenNames.has(source.node(id)?.name) : false),
    [hiddenNames, source],
  )
  const updateHidden = useCallback((next: HiddenConfig) => {
    setHidden(next)
    saveHidden(next)
  }, [])
  const hide = useCallback(
    (name: string) => {
      if (hidden.names.includes(name)) return
      updateHidden({ ...hidden, names: [...hidden.names, name] })
    },
    [hidden, updateHidden],
  )
  const unhide = useCallback(
    (name: string) => updateHidden({ ...hidden, names: hidden.names.filter((n) => n !== name) }),
    [hidden, updateHidden],
  )

  /**
   * Which declarations the views may show at all.
   *
   * The repository filter and the hidden list are the same operation, so they
   * are combined once here and applied to the source rather than re-derived by
   * each view.  Null means everything, which lets `filterSource` return the
   * index untouched instead of wrapping it in a predicate that always passes.
   */
  const accept = useMemo<Accept | null>(() => {
    const filtering = repoFilter.size > 0
    const hiding = hidden.active && hiddenNames.size > 0
    if (!source || (!filtering && !hiding)) return null
    return (id: NodeId) => {
      const decl = source.node(id)
      if (!decl) return false
      if (hiding && hiddenNames.has(decl.name)) return false
      return !filtering || repoFilter.has(source.repoOf(id))
    }
  }, [source, repoFilter, hidden.active, hiddenNames])

  /**
   * Trusted here, or vouched for by somebody you follow.
   *
   * Federated trust widens exactly this predicate and nothing else — the cut,
   * the green background and "up to trusted" mode all read from it, so a
   * certificate from someone you follow behaves like a mark you made yourself.
   */
  const isTrusted = useCallback(
    (id: NodeId) => {
      if (!source) return false
      if (marks.trusted.has(source.node(id)?.name)) return true
      if (federated.size === 0) return false
      const hash = source.hashOf(id)
      return hash.length > 0 && federated.has(hash)
    },
    [marks, source, federated],
  )
  /**
   * The index the views traverse.
   *
   * In "up to trusted" mode this is the index seen through the marks: trusted
   * declarations are leaves and characterized ones stand in for their own
   * dependencies.  Everything else — search, code, names — is untouched, so
   * only the shape of the dependency relation changes.
   */
  const viewSource = useMemo(
    () => (source && upToTrusted ? trustedCutSource(source, marks, root, isTrusted) : source),
    [source, upToTrusted, marks, root, isTrusted],
  )

  /** What the tree walks: the mode applied, then the filters. */
  const treeSource = useMemo(
    () => (viewSource ? filterSource(viewSource, accept) : null),
    [viewSource, accept],
  )

  /** The route from the root to the highlighted node, so the tree can open it. */
  const revealPath = useMemo(() => {
    if (!viewSource || root === null || selected === null || selected === root) return null
    return pathTo(treeSource ?? viewSource, root, selected, direction)
  }, [treeSource, viewSource, root, selected, direction])

  const isCharacterized = useCallback(
    (id: NodeId) => (source ? marks.characterized.has(source.node(id)?.name) : false),
    [marks, source],
  )

  // Stable identities: these are props of memoised components, so recreating
  // them on every render would defeat the memoisation entirely.
  /**
   * Make `id` the root, remembering where we were so `back` can return.
   *
   * The push is a plain call rather than nested inside a `setRoot` updater:
   * `StrictMode` invokes updaters twice, which would record every position
   * twice over.
   */
  const focus = useCallback(
    (id: NodeId) => {
      if (root !== null && root !== id) {
        setPast((stack) => [...stack, root].slice(-HISTORY_LIMIT))
      }
      setRoot(id)
      setSelected(id)
      setPicked(false)
    },
    [root],
  )

  const back = useCallback(() => {
    if (past.length === 0) return
    const previous = past[past.length - 1]
    setPast(past.slice(0, -1))
    setRoot(previous)
    setSelected(previous)
    setPicked(false)
  }, [past])

  const focusName = useCallback(
    (name: string) => {
      if (!source) return
      const id = source.findByName(name)
      if (id !== null) focus(id)
    },
    [source, focus],
  )

  const isKnown = useCallback(
    (name: string) => (source ? source.findByName(name) !== null : false),
    [source],
  )

  const pick = useCallback((id: NodeId) => {
    setSelected(id)
    setPicked(true)
  }, [])


  const searchDecls = useCallback(
    (text: string, limit: number) => (source ? source.search(text, limit) : []),
    [source],
  )

  /**
   * Apply one edit to the marks and persist it.
   *
   * The whole file is written back each time rather than patched: it is a few
   * kilobytes, and the dev server merges the hash snapshots it owns, so a
   * whole-file write cannot lose anything the browser does not know about.
   */
  const editMarks = useCallback(
    async (change: MarksEdit) => {
      const current = marks.marks
      const next = {
        ...current,
        trusted: [...current.trusted],
        characterizations: [...current.characterizations],
        protectedDecls: [...current.protectedDecls],
      }
      switch (change.kind) {
        case 'trust':
          next.trusted = [
            ...next.trusted.filter((m) => m.name !== change.name),
            // Pinned to the revision this index was built from: a judgement
            // about a declaration only means anything against a version of it.
            { name: change.name, commit: source?.meta().rev ?? '', note: change.note },
          ]
          break
        case 'untrust':
          next.trusted = next.trusted.filter((m) => m.name !== change.name)
          break
        case 'protect':
          next.protectedDecls = [
            ...next.protectedDecls.filter((p) => p.name !== change.name),
            { name: change.name, note: change.note, status: 'unrecorded' },
          ]
          break
        case 'unprotect':
          next.protectedDecls = next.protectedDecls.filter((p) => p.name !== change.name)
          break
        case 'characterize':
          next.characterizations = [
            ...next.characterizations.filter((c) => c.definition !== change.definition),
            { definition: change.definition, theorems: change.theorems, note: change.note },
          ]
          break
        case 'uncharacterize':
          next.characterizations = next.characterizations.filter(
            (c) => c.definition !== change.definition,
          )
          break
      }
      await saveMarks(next)
      setMarks(indexMarks(next, true))
    },
    [marks, source],
  )

  if (error) {
    return (
      <div className="app-message">
        <h1>trust</h1>
        <p className="error">Could not load the index: {error}</p>
        <p>
          Generate one with <code>trust export --repo core --out web/public/index Init</code>.
        </p>
      </div>
    )
  }

  if (!source) {
    // Nothing interactive is rendered until the index is in hand, so the load
    // cannot be raced by a click; `aria-busy` says the same thing to a screen
    // reader, which would otherwise be told only that the page is empty.
    const percent =
      progress && progress.phase === 'fetch' && progress.total > 0
        ? Math.min(100, Math.round((progress.loaded / progress.total) * 100))
        : null
    return (
      <div className="app-message" role="status" aria-busy="true" aria-live="polite">
        <h1>trust</h1>
        <p>{progress?.phase === 'build' ? 'Building index…' : 'Downloading index…'}</p>
        <div
          className="progress"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent ?? undefined}
        >
          <div
            className={percent === null ? 'progress-fill indeterminate' : 'progress-fill'}
            style={percent === null ? undefined : { width: `${percent}%` }}
          />
        </div>
        <p className="progress-detail">
          {percent === null
            ? 'This runs once per index; the page stays put until it is ready.'
            : `${formatBytes(progress!.loaded)} of ${formatBytes(progress!.total)} · ${percent}%`}
        </p>
      </div>
    )
  }

  const meta = source.meta()
  const rootDecl: Decl | null = root !== null ? source.node(root) : null

  const toggleRepo = (repo: string) => {
    const next = new Set(repoFilter)
    if (next.has(repo)) next.delete(repo)
    else next.add(repo)
    setRepoFilter(next)
  }

  if (expanded && rootDecl && root !== null) {
    return (
      <ExpandedGraph
        source={viewSource ?? source}
        root={root}
        rootName={rootDecl.name}
        direction={direction}
        depth={depth}
        selected={selected ?? root}
        onSelect={pick}
        onFocus={focus}
        dimUnconnected={picked}
        onDirection={setDirection}
        onDepth={setDepth}
        isTrusted={isTrusted}
        accept={accept ?? undefined}
        isHidden={isHidden}
        onHide={hide}
        onUnhide={unhide}
        repos={source.repos()}
        repoFilter={repoFilter}
        onRepoFilter={setRepoFilter}
        hidden={hidden}
        onHiddenChange={updateHidden}
        onClose={() => setExpanded(false)}
      />
    )
  }

  return (
    <div className="app">
      <header>
        <h1>trust</h1>
        <div className="meta">
          {meta.repo} @ Lean {meta.toolchain} · {meta.declCount.toLocaleString()} declarations ·{' '}
          {meta.stmtEdgeCount.toLocaleString()} statement edges
        </div>
      </header>

      <div className="controls">
        <button
          className="back"
          disabled={past.length === 0}
          onClick={back}
          title={
            past.length === 0
              ? 'Nothing to go back to'
              : `Back to ${source.node(past[past.length - 1])?.name ?? 'the previous declaration'}`
          }
        >
          ← back
        </button>
        <input
          className="search"
          value={query}
          placeholder="Search declarations…"
          onChange={(e) => setQuery(e.target.value)}
        />
        {hidden.names.length > 0 && (
          <button
            className={`chip mode ${hidden.active ? 'on' : ''}`}
            onClick={() => updateHidden({ ...hidden, active: !hidden.active })}
            title={`${hidden.names.length} declaration(s) hidden. Click to show them again.`}
          >
            hide hidden ({hidden.names.length})
          </button>
        )}
        <button
          className={`chip mode ${upToTrusted ? 'on' : ''}`}
          onClick={() => setUpToTrusted(!upToTrusted)}
          title="Stop tracing dependencies at declarations you have marked trusted, and show characterized definitions as their characterising theorems."
        >
          up to trusted
        </button>
        <div className="repos">
          <span className="label">Repositories</span>
          {source.repos().map((repo) => (
            <button
              key={repo}
              className={`chip ${repoFilter.size === 0 || repoFilter.has(repo) ? 'on' : ''}`}
              onClick={() => toggleRepo(repo)}
            >
              {repo}
            </button>
          ))}
          {repoFilter.size > 0 && (
            <button className="chip clear" onClick={() => setRepoFilter(new Set())}>
              clear
            </button>
          )}
        </div>
      </div>

      <div className="layout">
        <aside className="results">
          {results.map((decl) => (
            <button
              key={decl.id}
              className={`result ${decl.id === root ? 'active' : ''}`}
              onClick={() => focus(decl.id)}
            >
              <KindBadge decl={decl} />
              <span className="result-name">{decl.name}</span>
              <span className="result-module">{decl.module}</span>
            </button>
          ))}
          {results.length === 0 && <p className="empty">No matching declarations.</p>}
        </aside>

        <main>
          {rootDecl && root !== null ? (
            <>
              <section className="decl-header">
                <div className="decl-title">
                  <KindBadge decl={rootDecl} />
                  <h2>{rootDecl.name}</h2>
                </div>
                <div className="decl-module">{rootDecl.module}</div>
                <div className="decl-flags">
                  <span className={rootDecl.isData ? 'flag data' : 'flag prop'}>
                    {rootDecl.isData ? 'data-carrying' : 'proof'}
                  </span>
                  {rootDecl.usesSorry && <span className="flag sorry">uses sorry</span>}
                  {rootDecl.axioms && rootDecl.axioms.length > 0 && (
                    <span className="flag axioms">axioms: {rootDecl.axioms.join(', ')}</span>
                  )}
                </div>
              </section>

              {code && (
                <section className="code-pane">
                  {/* The docstring says what the declaration is for, which
                      nothing derived from the term can tell you. */}
                  {code.doc && <p className="docstring">{code.doc}</p>}
                  <CodeView block={code.signature} onSelectName={focusName} isKnown={isKnown} />
                  {code.value ? (
                    <>
                      {/* An inductive's body is its constructor list, which Lean
                          introduces with `where`, not with `:=`. */}
                      <div className="code-sep">
                        {rootDecl.kind === 'inductive' ? 'where' : ':='}
                      </div>
                      <CodeView block={code.value} onSelectName={focusName} isKnown={isKnown} />
                    </>
                  ) : (
                    rootDecl.isProp && <div className="code-note">proof omitted</div>
                  )}
                </section>
              )}

              <MarksPanel
                decl={rootDecl}
                marks={marks}
                onSelectName={focusName}
                isKnown={isKnown}
                search={searchDecls}
                onEdit={marks.editable ? editMarks : undefined}
              />

              <WhoTrusts
                decl={rootDecl}
                meta={meta}
                hasher={meta.hasher ?? 'semantic-v1'}
                identity={identity}
                following={following}
                onFollowingChange={() => void refreshFederation()}
              />

              <section className="direction">
                <button
                  className={direction === 'dependencies' ? 'on' : ''}
                  onClick={() => setDirection('dependencies')}
                >
                  ↓ dependencies
                </button>
                <button className={direction === 'dependents' ? 'on' : ''} onClick={() => setDirection('dependents')}>
                  ↑ dependents
                </button>
                <label>
                  depth
                  <input
                    type="range"
                    min={1}
                    max={8}
                    value={depth}
                    onChange={(e) => setDepth(Number(e.target.value))}
                  />
                  {depth}
                </label>
              </section>

              <div className="panes">
                <section className="pane tree-pane">
                  <h3>{direction === 'dependencies' ? 'Definitional dependencies' : 'Dependents'}</h3>
                  <DepsTree
                    key={`${root}-${direction}-${upToTrusted}`}
                    source={treeSource ?? source}
                    id={root}
                    direction={direction}
                    onSelect={focus}
                    selected={selected}
                    revealPath={revealPath}
                    isTrusted={isTrusted}
                    isCharacterized={upToTrusted ? isCharacterized : undefined}
                  />
                </section>

                <section className="pane graph-pane">
                  <div className="pane-head">
                    <h3>Graph</h3>
                    <button className="expand" onClick={() => setExpanded(true)}>
                      expand ⤢
                    </button>
                  </div>
                  <GraphView
                    source={viewSource ?? source}
                    root={root}
                    direction={direction}
                    depth={depth}
                    selected={selected ?? root}
                    onSelect={pick}
                    onFocus={focus}
                    dimUnconnected={picked}
                    isTrusted={isTrusted}
                    accept={accept ?? undefined}
                    isHidden={isHidden}
                    onHide={hide}
                    onUnhide={unhide}
                  />
                </section>
              </div>

            </>
          ) : (
            <p className="empty">Select a declaration to begin.</p>
          )}
        </main>
      </div>
    </div>
  )
}