import { setTimeout as delay } from "node:timers/promises";

/** One restoration budget, independent of scan cancellation. The parent gives
 * the worker an additional flush margin before resorting to termination. */
export const cleanupTimeoutMs = 120_000;
export const workerRestorationGraceMs = cleanupTimeoutMs + 15_000;

export class CleanupExecution {
  private readonly controller = new AbortController();
  private timer?: ReturnType<typeof setTimeout>;
  private started = false;
  public readonly signal: AbortSignal = this.controller.signal;

  public constructor(private readonly timeoutMs = cleanupTimeoutMs, private readonly parent?: AbortSignal) {
    parent?.addEventListener("abort", this.start, { once: true });
    if (parent?.aborted) this.start();
  }

  /** Start on cleanup entry (including its first wait), never at case creation. */
  public readonly start = (): AbortSignal => {
    if (!this.started) {
      this.started = true;
      this.timer = setTimeout(() => this.controller.abort(new Error("CLEANUP_DEADLINE_EXCEEDED")), this.timeoutMs);
      this.timer.unref();
    }
    return this.signal;
  };

  public async wait(milliseconds: number): Promise<void> {
    await delay(milliseconds, undefined, { signal: this.start() });
  }

  public dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.parent?.removeEventListener("abort", this.start);
  }
}
