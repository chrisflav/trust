/**
 * Declarations this reader does not want to look at.
 *
 * Deliberately *not* part of `trust-marks.json`.  A mark is a claim about a
 * declaration — someone vouched for it, or watched it — and belongs in version
 * control where others can see and review it.  Hiding something is a statement
 * about the reader, not about the declaration: `instHAdd` is not less
 * trustworthy for being noise in your graph.  So it lives in this browser,
 * survives reloads, and is nobody else's business.
 */

const STORAGE_KEY = 'trust:hidden-declarations'

export interface HiddenConfig {
  /** Fully qualified names the reader has hidden. */
  names: string[]
  /** Whether hiding is currently in effect; on by default. */
  active: boolean
}

export const defaultHidden: HiddenConfig = { names: [], active: true }

/** Read the config, tolerating anything a previous version may have left. */
export function loadHidden(): HiddenConfig {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return defaultHidden
    const parsed = JSON.parse(raw) as Partial<HiddenConfig>
    return {
      names: Array.isArray(parsed.names) ? parsed.names.filter((n) => typeof n === 'string') : [],
      // Absent means an older config, which predates the toggle: hiding on.
      active: parsed.active !== false,
    }
  } catch {
    // A corrupt or unavailable store must not stop the page from coming up.
    return defaultHidden
  }
}

export function saveHidden(config: HiddenConfig): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(config))
  } catch {
    // Private browsing, a full quota: hiding simply does not persist.
  }
}
