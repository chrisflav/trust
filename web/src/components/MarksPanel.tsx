import { useMemo, useState } from 'react'
import type { MarksIndex } from '../data/marks'
import type { Decl, ProtectionStatus } from '../data/types'
import { KindBadge } from './KindBadge'

/** Suggestions shown under the characterising-theorem box. */
const SUGGESTION_LIMIT = 8

/**
 * How many matches to ask for before ranking.
 *
 * Proofs are floated to the top, so the search has to return more than fits in
 * the list or a definition-heavy prefix like `Finset` would crowd out every
 * theorem before the ranking ever ran.
 */
const SUGGESTION_POOL = 80

/** How each protection verdict reads, and whether it is bad news. */
const PROTECTION_TEXT: Record<ProtectionStatus, { label: string; tone: string; title: string }> = {
  unchanged: {
    label: 'protected',
    tone: 'ok',
    title: 'Content matches the recorded snapshot.',
  },
  changed: {
    label: 'CHANGED since snapshot',
    tone: 'alarm',
    title: 'Content no longer matches the recorded snapshot.',
  },
  unrecorded: {
    label: 'protected, no snapshot',
    tone: 'warn',
    title: 'Protected, but no hash has been recorded yet. Run `trust protect` to record one.',
  },
  missing: {
    label: 'protected, missing',
    tone: 'alarm',
    title: 'Protected, but not present in the exported environment.',
  },
  incomparable: {
    label: 'protected, incomparable',
    tone: 'warn',
    title: 'The recorded snapshot came from a different hasher, so it cannot be compared.',
  },
}

interface MarksPanelProps {
  decl: Decl
  marks: MarksIndex
  onSelectName: (name: string) => void
  isKnown: (name: string) => boolean
  /** Matching declarations, for the characterising-theorem typeahead. */
  search: (query: string, limit: number) => Decl[]
  /** Apply an edit; absent when the marks are read-only. */
  onEdit?: (change: MarksEdit) => Promise<void>
}

/** The edits the panel can ask for. */
export type MarksEdit =
  | { kind: 'trust'; name: string; note: string }
  | { kind: 'untrust'; name: string }
  | { kind: 'protect'; name: string; note: string }
  | { kind: 'unprotect'; name: string }
  | { kind: 'characterize'; definition: string; theorems: string[]; note: string }
  | { kind: 'uncharacterize'; definition: string }

/**
 * The judgements recorded about one declaration, and a way to change them.
 *
 * Read-only unless the dev server's marks API is answering: a deployed index is
 * a static site with nowhere to write.  Recording a *hash* still needs Lean
 * even in development, so protecting from here marks the declaration and leaves
 * the snapshot for `trust protect`.
 */
export function MarksPanel({
  decl,
  marks,
  onSelectName,
  isKnown,
  search,
  onEdit,
}: MarksPanelProps) {
  const trusted = marks.trusted.get(decl.name)
  const characterization = marks.characterized.get(decl.name)
  const protection = marks.protectedDecls.get(decl.name)
  const [busy, setBusy] = useState(false)
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [highlight, setHighlight] = useState(0)

  const already = characterization?.theorems ?? []

  /**
   * What to offer for the half-typed name.
   *
   * A characterization is made of theorems, so proofs come first — searching
   * `Finset` otherwise returns a screen of definitions and instances before the
   * first lemma.  Non-proofs are kept below rather than dropped: the box also
   * accepts anything the index knows, and silently hiding a name the user is
   * deliberately typing would be worse than ordering it last.
   */
  const suggestions = useMemo(() => {
    const query = draft.trim()
    // Only the last name is completed, so pasting a list still works.
    const last = query.split(/[\s,]+/).filter((part) => part.length > 0).pop() ?? ''
    if (last.length === 0) return []
    const found = search(last, SUGGESTION_POOL).filter(
      (candidate) => candidate.name !== decl.name && !already.includes(candidate.name),
    )
    const proofs = found.filter((candidate) => candidate.isProp)
    const rest = found.filter((candidate) => !candidate.isProp)
    return [...proofs, ...rest].slice(0, SUGGESTION_LIMIT)
  }, [draft, search, decl.name, already])

  const apply = async (change: MarksEdit) => {
    if (!onEdit) return
    setBusy(true)
    setError(null)
    try {
      await onEdit(change)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const addNames = async (names: string[]) => {
    if (names.length === 0) return
    const unknown = names.filter((name) => !isKnown(name))
    if (unknown.length > 0) {
      setError(`not in this index: ${unknown.join(', ')}`)
      return
    }
    const merged = [...already]
    for (const name of names) if (!merged.includes(name)) merged.push(name)
    await apply({
      kind: 'characterize',
      definition: decl.name,
      theorems: merged,
      note: characterization?.note ?? '',
    })
    setDraft('')
    setHighlight(0)
  }

  const tokens = () => draft.split(/[\s,]+/).filter((part) => part.length > 0)

  const addFromDraft = () => addNames(tokens())

  /** Complete the name being typed, keeping any that were typed before it. */
  const acceptSuggestion = (name: string) => {
    const parts = tokens()
    if (parts.length === 0) return addNames([name])
    parts[parts.length - 1] = name
    return addNames(parts)
  }

  const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      setDraft('')
      setHighlight(0)
      return
    }
    if (suggestions.length > 0 && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
      event.preventDefault()
      const step = event.key === 'ArrowDown' ? 1 : suggestions.length - 1
      setHighlight((current) => (current + step) % suggestions.length)
      return
    }
    if (event.key === 'Enter') {
      event.preventDefault()
      // Enter takes the highlighted suggestion when there is one, so the common
      // case is type-a-few-letters-and-press-Enter rather than typing a name in
      // full and hoping it is spelled the way Lean spells it.
      const chosen = suggestions[highlight]
      void (chosen ? acceptSuggestion(chosen.name) : addFromDraft())
    }
  }

  const dropTheorem = async (name: string) => {
    const rest = (characterization?.theorems ?? []).filter((t) => t !== name)
    if (rest.length === 0) {
      await apply({ kind: 'uncharacterize', definition: decl.name })
    } else {
      await apply({
        kind: 'characterize',
        definition: decl.name,
        theorems: rest,
        note: characterization?.note ?? '',
      })
    }
  }

  const verdict = protection ? PROTECTION_TEXT[protection.status] : null

  return (
    <section className="marks">
      <div className="marks-row">
        <h3>Judgements</h3>
        {!marks.editable && (
          <span className="marks-readonly" title="Editing needs the dev server's marks API.">
            read-only
          </span>
        )}
      </div>

      <div className="marks-flags">
        {trusted && (
          <span className="mark trusted" title={trusted.note || 'Marked trusted.'}>
            trusted{trusted.commit && ` at ${trusted.commit}`}
          </span>
        )}
        {verdict && protection && (
          <span className={`mark protection ${verdict.tone}`} title={verdict.title}>
            {verdict.label}
            {protection.status === 'changed' && protection.recordedAt && (
              <> (recorded at {protection.recordedAt})</>
            )}
          </span>
        )}
        {!trusted && !protection && !characterization && (
          <span className="marks-empty">Nothing recorded about this declaration.</span>
        )}
      </div>

      {characterization && (
        <div className="characterization">
          <span className="characterization-label" title={characterization.note}>
            characterized by
          </span>
          {characterization.theorems.map((name) => (
            <span key={name} className="characterization-thm">
              <button className="decl-name" onClick={() => onSelectName(name)}>
                {name}
              </button>
              {onEdit && (
                <button
                  className="mark-drop"
                  disabled={busy}
                  title={`Remove ${name} from the characterization`}
                  onClick={() => dropTheorem(name)}
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
      )}

      {onEdit && (
        <div className="marks-actions">
          <button
            disabled={busy}
            onClick={() =>
              trusted
                ? apply({ kind: 'untrust', name: decl.name })
                : apply({ kind: 'trust', name: decl.name, note: '' })
            }
          >
            {trusted ? 'untrust' : 'mark trusted'}
          </button>
          <button
            disabled={busy}
            onClick={() =>
              protection
                ? apply({ kind: 'unprotect', name: decl.name })
                : apply({ kind: 'protect', name: decl.name, note: '' })
            }
          >
            {protection ? 'unprotect' : 'protect'}
          </button>
          <div className="marks-typeahead">
            <input
              className="marks-input"
              value={draft}
              placeholder="characterising theorem…"
              disabled={busy}
              autoComplete="off"
              aria-autocomplete="list"
              aria-expanded={suggestions.length > 0}
              onChange={(e) => {
                setDraft(e.target.value)
                setHighlight(0)
                setError(null)
              }}
              onKeyDown={onKeyDown}
            />
            {suggestions.length > 0 && (
              <ul className="marks-suggestions" role="listbox">
                {suggestions.map((candidate, index) => (
                  <li key={candidate.id} role="option" aria-selected={index === highlight}>
                    <button
                      className={index === highlight ? 'suggestion on' : 'suggestion'}
                      // `mousedown` rather than `click`, so choosing with the
                      // mouse is not lost to the input blurring first.
                      onMouseDown={(e) => {
                        e.preventDefault()
                        void acceptSuggestion(candidate.name)
                      }}
                      onMouseEnter={() => setHighlight(index)}
                    >
                      <KindBadge decl={candidate} />
                      <span className="suggestion-name">{candidate.name}</span>
                      <span className="suggestion-module">{candidate.module}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <button disabled={busy || draft.trim().length === 0} onClick={() => void addFromDraft()}>
            add
          </button>
        </div>
      )}

      {protection?.status === 'unrecorded' && (
        <p className="marks-hint">
          Recording a hash needs Lean; run <code>trust protect &lt;module&gt; {decl.name}</code>.
        </p>
      )}
      {error && <p className="marks-error">{error}</p>}
    </section>
  )
}
