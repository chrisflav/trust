import {
  buildIndexPayload,
  fetchIndexParts,
  payloadTransferables,
  type LoadProgress,
  type WorkerMessage,
} from './source'

/**
 * Builds an index off the main thread.
 *
 * Fetching, parsing 226,368 declarations and building three adjacencies is a
 * single synchronous task; on the main thread it froze the page for 313 ms
 * while it ran.  Here the result is handed back as typed arrays, which
 * `postMessage` transfers rather than copies, so the main thread only pays for
 * the two name blobs.
 *
 * Progress is reported as it goes: an index is tens of megabytes, and the page
 * has nothing to show until the whole of it has arrived.
 *
 * One build per worker: `StaticIndexSource.load` terminates it on the reply.
 */
self.onmessage = async (event: MessageEvent<{ base: string }>) => {
  const post = self as unknown as Worker
  const send = (message: WorkerMessage, transfer?: ArrayBuffer[]) =>
    transfer ? post.postMessage(message, transfer) : post.postMessage(message)
  try {
    const onProgress = (progress: LoadProgress) => send({ type: 'progress', progress })
    const parts = await fetchIndexParts(event.data.base, onProgress)
    onProgress({ phase: 'build', loaded: 0, total: 0 })
    const payload = buildIndexPayload(
      parts.metaText,
      parts.declText,
      parts.stmtPairs,
      parts.bodyPairs,
    )
    send(
      { type: 'done', payload, hasCode: parts.meta.hasCode === true },
      payloadTransferables(payload),
    )
  } catch (error) {
    // The caller falls back to building inline, so a failure here is recoverable.
    send({ type: 'error', error: String(error) })
  }
}