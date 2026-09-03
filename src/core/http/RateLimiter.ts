export class RateLimiter {
  private nextAvailableAt = 0;
  private queue: Promise<void> = Promise.resolve();

  public constructor(private readonly requestsPerSecond: number) {}

  public async wait(signal?: AbortSignal, count = 1): Promise<void> {
    if (!Number.isInteger(count) || count < 1) throw new Error("RATE_LIMIT_RESERVATION_INVALID");
    let releaseTurn!: () => void;
    const turn = new Promise<void>((resolve) => { releaseTurn = resolve; });
    const previous = this.queue;
    this.queue = previous.then(() => turn, () => turn);
    try {
      await waitForTurn(previous, signal);
      const intervalMs = Math.ceil(1000 / this.requestsPerSecond);
      const delayMs = Math.max(0, this.nextAvailableAt - Date.now());
      if (delayMs > 0) {
        const { setTimeout } = await import("node:timers/promises");
        await setTimeout(delayMs, undefined, { ...(signal ? { signal } : {}) });
      }
      if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
      // Anchor the next slot to the actual release time. This prevents late
      // event-loop wakeups from bunching queued requests to catch up.
      this.nextAvailableAt = Date.now() + (intervalMs * count);
    } finally {
      releaseTurn();
    }
  }
}

async function waitForTurn(previous: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (!signal) return previous;
  if (signal.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
  let rejectAborted!: (reason: unknown) => void;
  const aborted = new Promise<never>((_resolve, reject) => { rejectAborted = reject; });
  const onAbort = () => rejectAborted(signal.reason ?? new DOMException("The operation was aborted", "AbortError"));
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await Promise.race([previous, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

export function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}
