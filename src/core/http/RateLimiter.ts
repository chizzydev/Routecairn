export class RateLimiter {
  private nextAvailableAt = 0;

  public constructor(private readonly requestsPerSecond: number) {}

  public async wait(): Promise<void> {
    const intervalMs = Math.ceil(1000 / this.requestsPerSecond);
    const now = Date.now();
    const scheduledAt = Math.max(now, this.nextAvailableAt);
    this.nextAvailableAt = scheduledAt + intervalMs;
    const delayMs = scheduledAt - now;

    if (delayMs > 0) {
      await sleep(delayMs);
    }
  }
}

export function sleep(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}
