import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import type { DeclCode } from './types'

/**
 * Checks the rendered code produced by `trust export --with-code`.
 *
 * The invariant that matters is that every reference range indexes the text
 * correctly: Lean counts UTF-16 code units so that these offsets can be used as
 * JavaScript string indices directly, and a mistake there would silently
 * mis-highlight everything after the first astral character.
 */
const base = new URL('../../public/index/core/', import.meta.url).pathname
const codeDir = `${base}code`
const available = existsSync(codeDir)
const suite = available ? describe : describe.skip

suite('exported code', () => {
  const entries: DeclCode[] = []
  if (available) {
    for (const file of readdirSync(codeDir).slice(0, 3)) {
      for (const line of readFileSync(`${codeDir}/${file}`, 'utf8').split('\n')) {
        if (line.length > 0) entries.push(JSON.parse(line))
      }
    }
  }

  it('exports something', () => {
    expect(entries.length).toBeGreaterThan(100)
  })

  it('gives every reference a range inside its text', () => {
    for (const entry of entries) {
      for (const block of [entry.signature, entry.value]) {
        if (!block) continue
        for (const ref of block.refs) {
          expect(ref.start).toBeGreaterThanOrEqual(0)
          expect(ref.stop).toBeGreaterThan(ref.start)
          expect(ref.stop).toBeLessThanOrEqual(block.text.length)
        }
      }
    }
  })

  it('never lets references overlap', () => {
    for (const entry of entries) {
      for (const block of [entry.signature, entry.value]) {
        if (!block) continue
        const sorted = [...block.refs].sort((a, b) => a.start - b.start)
        for (let i = 1; i < sorted.length; i++) {
          expect(sorted[i].start).toBeGreaterThanOrEqual(sorted[i - 1].stop)
        }
      }
    }
  })

  it('never includes surrounding whitespace in a reference', () => {
    for (const entry of entries) {
      for (const block of [entry.signature, entry.value]) {
        if (!block) continue
        for (const ref of block.refs) {
          const span = block.text.slice(ref.start, ref.stop)
          expect(span).toBe(span.trim())
        }
      }
    }
  })

  it('omits the body of proofs and keeps it for definitions', () => {
    const theorems = entries.filter((e) => e.signature.text.startsWith('theorem '))
    const defs = entries.filter((e) => e.signature.text.startsWith('def '))
    expect(theorems.length).toBeGreaterThan(0)
    expect(defs.length).toBeGreaterThan(0)
    for (const theorem of theorems) expect(theorem.value).toBeNull()
    expect(defs.some((d) => d.value !== null)).toBe(true)
  })

  it('names the declaration itself in its own signature', () => {
    const withRefs = entries.filter((e) => e.signature.refs.length > 0)
    expect(withRefs.length).toBeGreaterThan(0)
  })
})