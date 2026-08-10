/**
 * Talking to another node.
 *
 * Everything a peer sends is untrusted input, including its size and how long
 * it takes to arrive.  So every request here is bounded three ways — a
 * deadline, a byte cap, and a refusal to follow redirects — and the address is
 * re-checked each time rather than once when the peer was added.
 */

import type { Policy } from '../config'
import { checkPeerUrl } from './address'
import { parseBundle, parseDescriptor, type Bundle, type Descriptor } from './protocol'

export interface FetchOptions {
  policy: Policy
  /** Overrides `policy.peerTimeoutMs` when a caller has a tighter budget. */
  timeoutMs?: number
  signal?: AbortSignal
  method?: 'GET' | 'POST'
  body?: unknown
}

/**
 * A JSON GET or POST with a hard ceiling on what it will read.
 *
 * The cap is enforced while streaming rather than after: `await
 * response.json()` on a peer that answers with an endless body is how a node
 * runs out of memory, and `Content-Length` is a claim by the same peer.
 */
export async function fetchJson(
  url: string,
  options: FetchOptions,
): Promise<unknown | { error: string }> {
  // A request URL, not a peer identity: the endpoint and its parameters are
  // part of it, but the address it resolves to is checked exactly the same way.
  const checked = await checkPeerUrl(url, options.policy, { allowQuery: true })
  if ('error' in checked) return { error: checked.error }

  const timeout = AbortSignal.timeout(options.timeoutMs ?? options.policy.peerTimeoutMs)
  const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout

  let response: Response
  try {
    response = await fetch(url, {
      method: options.method ?? 'GET',
      // A redirect is a second URL that never went through the address check.
      // Refusing them costs a peer nothing — it knows its own address — and
      // removes the easy way to bounce a request somewhere private.
      redirect: 'error',
      signal,
      headers: {
        Accept: 'application/json',
        ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return { error: `could not reach ${url}: ${reason}` }
  }

  const declared = Number(response.headers.get('content-length') ?? '0')
  if (declared > options.policy.maxResponseBytes) {
    return { error: `${url} offered ${declared} bytes; the limit is ${options.policy.maxResponseBytes}` }
  }

  const text = await readCapped(response, options.policy.maxResponseBytes)
  if (typeof text !== 'string') return text

  if (!response.ok) {
    return { error: `${url} answered ${response.status}: ${text.slice(0, 200)}` }
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    return { error: `${url} did not answer with JSON` }
  }
}

async function readCapped(response: Response, limit: number): Promise<string | { error: string }> {
  if (!response.body) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > limit) {
        await reader.cancel()
        return { error: `response exceeded ${limit} bytes` }
      }
      chunks.push(value)
    }
  } catch (error) {
    return { error: `truncated response: ${error instanceof Error ? error.message : String(error)}` }
  }
  return Buffer.concat(chunks).toString('utf8')
}

export async function fetchDescriptor(
  base: string,
  options: FetchOptions,
): Promise<Descriptor | { error: string }> {
  const body = await fetchJson(`${base}/api/federation`, options)
  if (body !== null && typeof body === 'object' && 'error' in body) {
    return body as { error: string }
  }
  return parseDescriptor(body)
}

export async function fetchBundle(
  base: string,
  since: string | undefined,
  options: FetchOptions,
): Promise<Bundle | { error: string }> {
  const query = new URLSearchParams({ limit: String(options.policy.maxEntries) })
  if (since) query.set('since', since)
  const body = await fetchJson(`${base}/api/certificates/export?${query}`, options)
  if (body !== null && typeof body === 'object' && 'error' in body) {
    return body as { error: string }
  }
  return parseBundle(body)
}

export interface PeerQuery {
  hash?: string
  hasher?: string
  fingerprint?: string
  depth: number
  via: string[]
}

/**
 * Ask a peer the question we were asked, one hop shallower.
 *
 * The answer comes back as a bundle rather than as the peer's own response
 * shape, so that a relayed entry is checked by exactly the same rules as an
 * imported one.  A node should not have two notions of what it will believe.
 */
export async function queryPeer(
  base: string,
  query: PeerQuery,
  options: FetchOptions,
): Promise<Bundle | { error: string }> {
  const params = new URLSearchParams({ depth: String(query.depth), format: 'bundle' })
  if (query.hash) params.set('hash', query.hash)
  if (query.hasher) params.set('hasher', query.hasher)
  if (query.fingerprint) params.set('fingerprint', query.fingerprint)
  if (query.via.length > 0) params.set('via', query.via.join(','))
  const body = await fetchJson(`${base}/api/certificates?${params}`, options)
  if (body !== null && typeof body === 'object' && 'error' in body) {
    return body as { error: string }
  }
  return parseBundle(body)
}
