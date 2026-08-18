import { describe, expect, it } from 'vitest'
import { createSerialQueue } from '../shared/utils/serial-queue'

/** A promise the test resolves by hand, so overlap is observable. */
function deferred<T = void>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('createSerialQueue', () => {
  it('does not start the next piece of work until the previous one settles', async () => {
    // The whole point: a signer asked to approve two things at once refuses
    // the second. Overlap is the bug, not slowness.
    const queue = createSerialQueue()
    const first = deferred()
    const started: string[] = []

    const a = queue(async () => {
      started.push('a')
      await first.promise
    })
    const b = queue(async () => {
      started.push('b')
    })

    await Promise.resolve()
    expect(started).toEqual(['a'])

    first.resolve()
    await Promise.all([a, b])
    expect(started).toEqual(['a', 'b'])
  })

  it('runs queued work in the order it was requested', async () => {
    const queue = createSerialQueue()
    const order: number[] = []

    await Promise.all([1, 2, 3].map(n => queue(async () => {
      order.push(n)
    })))

    expect(order).toEqual([1, 2, 3])
  })

  it('runs later work after an earlier failure, and only its own caller sees that failure', async () => {
    // One list failing to load must not strand the other two behind a
    // rejected promise — the page would then wait forever for requests that
    // never ran.
    const queue = createSerialQueue()

    const failed = queue(async () => {
      throw new Error('refused')
    })
    const after = queue(async () => 'ran')

    await expect(failed).rejects.toThrow('refused')
    await expect(after).resolves.toBe('ran')
  })

  it('returns each caller its own result', async () => {
    const queue = createSerialQueue()
    const results = await Promise.all([
      queue(async () => 'first'),
      queue(async () => 'second')
    ])
    expect(results).toEqual(['first', 'second'])
  })
})
