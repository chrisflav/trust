import type { Characterization, Marks, ProtectedMark, TrustMark } from './types'

/**
 * Human judgements about declarations, and where they come from.
 *
 * Two sources, because they answer different questions.  The index's
 * `marks.json` is written by `trust export` and is the only thing that knows
 * whether a protected declaration still matches its snapshot — deciding that
 * needs the Lean environment.  The dev server's `/api/marks` reads
 * `trust-marks.json` directly, so edits show up without re-exporting an index
 * that takes twenty-five minutes to build at Mathlib scale.
 *
 * When both are present the live file decides *which* declarations are marked
 * and the exported one supplies the protection verdicts.  A declaration
 * protected since the last export therefore reads as `unrecorded`, which is
 * exactly what it is.
 */
export interface MarksIndex {
  /** The marks themselves, as edited. */
  marks: Marks
  trusted: Map<string, TrustMark>
  characterized: Map<string, Characterization>
  protectedDecls: Map<string, ProtectedMark>
  /** Whether `/api/marks` is answering, i.e. whether edits can be saved. */
  editable: boolean
}

/** The API the dev server exposes; absent from a static deployment. */
const MARKS_API = '/api/marks'

export const emptyMarks: Marks = {
  version: 1,
  trusted: [],
  characterizations: [],
  protectedDecls: [],
}

/** Translate the wire form, whose `protected` key is a reserved word here. */
function parseMarks(value: unknown): Marks {
  const raw = (value ?? {}) as Record<string, unknown>
  return {
    version: typeof raw.version === 'number' ? raw.version : 1,
    hasher: typeof raw.hasher === 'string' ? raw.hasher : undefined,
    trusted: Array.isArray(raw.trusted) ? (raw.trusted as TrustMark[]) : [],
    characterizations: Array.isArray(raw.characterizations)
      ? (raw.characterizations as Characterization[])
      : [],
    protectedDecls: Array.isArray(raw.protected) ? (raw.protected as ProtectedMark[]) : [],
  }
}

/**
 * The wire form again, for writing back.
 *
 * Only the parts a person edits are sent.  `status` and the hashes are derived
 * by the exporter, and the recorded snapshots are the one thing here that
 * cannot be recomputed — losing them would throw away the history that makes a
 * protected declaration worth protecting — so the browser never sends them and
 * the dev server merges them back from the file it already has.
 */
export function serializeMarks(marks: Marks): unknown {
  return {
    version: marks.version,
    trusted: marks.trusted,
    characterizations: marks.characterizations,
    protected: marks.protectedDecls.map((entry) => ({ name: entry.name, note: entry.note })),
  }
}

async function fetchJson(url: string): Promise<unknown | null> {
  try {
    const response = await fetch(url)
    if (!response.ok) return null
    return await response.json()
  } catch {
    return null
  }
}

/** Build the lookup maps a view needs from a set of marks. */
export function indexMarks(marks: Marks, editable: boolean): MarksIndex {
  return {
    marks,
    editable,
    trusted: new Map(marks.trusted.map((m) => [m.name, m])),
    characterized: new Map(marks.characterizations.map((c) => [c.definition, c])),
    protectedDecls: new Map(marks.protectedDecls.map((p) => [p.name, p])),
  }
}

/** Load the marks for an index, from the dev API when it is available. */
export async function loadMarks(base: string): Promise<MarksIndex> {
  const [live, exported] = await Promise.all([fetchJson(MARKS_API), fetchJson(`${base}/marks.json`)])
  if (live === null) {
    // Static deployment: the exported file is all there is, and it cannot be edited.
    return indexMarks(exported === null ? emptyMarks : parseMarks(exported), false)
  }
  const marks = parseMarks(live)
  const statuses = new Map(
    parseMarks(exported ?? {}).protectedDecls.map((entry) => [entry.name, entry]),
  )
  // Membership comes from the live file, verdicts from the exported one.
  marks.protectedDecls = marks.protectedDecls.map((entry) => {
    const known = statuses.get(entry.name)
    return known ? { ...entry, ...known, note: entry.note } : { ...entry, status: 'unrecorded' }
  })
  marks.hasher = parseMarks(exported ?? {}).hasher
  return indexMarks(marks, true)
}

/** Persist marks through the dev API.  Throws when it is not available. */
export async function saveMarks(marks: Marks): Promise<void> {
  const response = await fetch(MARKS_API, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(serializeMarks(marks)),
  })
  if (!response.ok) throw new Error(`could not save marks: ${response.status}`)
}
