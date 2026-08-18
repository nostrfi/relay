/**
 * Runs asynchronous work one piece at a time, in the order it was queued.
 *
 * Signers are single-approval devices. A NIP-07 extension asked to sign
 * while an approval is already open on screen does not queue the second
 * request — it rejects it outright with "Another approval request is
 * already pending" — and a NIP-46 bunker has one RPC channel per pairing.
 * Any page that issues two privileged calls at once therefore fails on the
 * second, which is what the moderation page did when it loaded its three
 * lists with Promise.all (nostrfi/workspace#38).
 *
 * Kept out of the composable, and free of any signer vocabulary, so the
 * ordering guarantees below can be tested without a browser or a signer.
 */
export function createSerialQueue() {
  let tail: Promise<unknown> = Promise.resolve()

  return function enqueue<T>(work: () => Promise<T>): Promise<T> {
    const result = tail.then(work)
    // The queue keeps order; it does not propagate outcomes. Without this,
    // one rejected call would leave every later one chained behind a
    // rejected promise and never run.
    tail = result.then(() => {}, () => {})
    return result
  }
}
