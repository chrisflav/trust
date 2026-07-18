import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import type { Plugin } from 'vite'

/**
 * Read and write `trust-marks.json` from the dev server.
 *
 * `DESIGN.md` asks for an *interactive* way to declare declarations trusted and
 * to record characterizations, and for those judgements to live in a
 * version-controlled file.  A static site cannot write files, so the editing
 * half only exists while `vite dev` is running; a deployed index shows the
 * marks read-only.
 *
 * Snapshots are merged here rather than sent by the browser.  A hash snapshot
 * is the one part of the file that cannot be recomputed from the environment,
 * and a round trip through a client that has no reason to know about it is
 * exactly how such things get dropped.  So the server keeps them: the browser
 * says which declarations are marked and why, and the existing history stays
 * attached to them.
 *
 * Recording a *new* hash still needs Lean, so a declaration protected from the
 * browser has no snapshot until `trust protect` is run for it, and reports
 * itself as `unrecorded` until then.
 */

interface Snapshot {
  commit: string
  hash: string
  hasher: string
}

interface ProtectedEntry {
  name: string
  note?: string
  snapshots?: Snapshot[]
}

interface MarksFile {
  version?: number
  trusted?: unknown[]
  characterizations?: unknown[]
  protected?: ProtectedEntry[]
}

const EMPTY: MarksFile = { version: 1, trusted: [], characterizations: [], protected: [] }

function readMarks(path: string): MarksFile {
  if (!existsSync(path)) return EMPTY
  const text = readFileSync(path, 'utf8')
  if (text.trim().length === 0) return EMPTY
  return JSON.parse(text) as MarksFile
}

/** Keep the incoming edits, but carry each protected entry's history forward. */
function mergeSnapshots(incoming: MarksFile, existing: MarksFile): MarksFile {
  const known = new Map((existing.protected ?? []).map((entry) => [entry.name, entry]))
  return {
    version: incoming.version ?? 1,
    trusted: incoming.trusted ?? [],
    characterizations: incoming.characterizations ?? [],
    protected: (incoming.protected ?? []).map((entry) => ({
      name: entry.name,
      note: entry.note ?? '',
      snapshots: known.get(entry.name)?.snapshots ?? [],
    })),
  }
}

function readBody(request: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = ''
    request.on('data', (chunk) => (body += chunk))
    request.on('end', () => resolve(body))
    request.on('error', reject)
  })
}

export function marksApi(marksPath: string): Plugin {
  return {
    name: 'trust-marks-api',
    // Dev only: `apply: 'serve'` keeps this out of the production build, where
    // there is no server to write anything.
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use('/api/marks', async (request, response) => {
        const send = (status: number, body: unknown) => {
          response.statusCode = status
          response.setHeader('Content-Type', 'application/json')
          response.end(JSON.stringify(body))
        }
        try {
          if (request.method === 'GET') {
            return send(200, readMarks(marksPath))
          }
          if (request.method === 'PUT') {
            const incoming = JSON.parse(await readBody(request)) as MarksFile
            const merged = mergeSnapshots(incoming, readMarks(marksPath))
            // Sorted and pretty-printed, matching what `trust` itself writes, so
            // that editing from either side produces the same diff.
            merged.trusted = sortBy(merged.trusted as { name: string }[], (m) => m.name)
            merged.characterizations = sortBy(
              merged.characterizations as { definition: string }[],
              (c) => c.definition,
            )
            merged.protected = sortBy(merged.protected ?? [], (p) => p.name)
            writeFileSync(marksPath, `${JSON.stringify(merged, null, 1)}\n`)
            return send(200, merged)
          }
          send(405, { error: `unsupported method ${request.method}` })
        } catch (error) {
          send(500, { error: String(error) })
        }
      })
    },
  }
}

function sortBy<T>(items: T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0))
}
