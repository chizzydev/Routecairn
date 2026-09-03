import { ScanCancelledError } from "../engine/ScanEvents.js";
import { RateLimiter } from "./RateLimiter.js";

export type RequestLedgerLane = "SCAN" | "CLEANUP";

export interface ScanRequestLedgerSnapshot {
  maxRequests: number;
  cleanupReservedRequests: number;
  scanCapacity: number;
  scanTransmitted: number;
  cleanupTransmitted: number;
  totalTransmitted: number;
  scanRemaining: number;
  cleanupRemaining: number;
  inFlight: number;
  queued: number;
}

export type ScanRequestLedgerUpdate = (snapshot: ScanRequestLedgerSnapshot, budgetChanged: boolean) => void;

interface Waiter {
  lane: RequestLedgerLane;
  resolve: (release: () => void) => void;
  reject: (error: Error) => void;
  signal?: AbortSignal;
  abort?: () => void;
}

/**
 * Authoritative scan-wide accounting for physical network transmissions.
 * The ordinary lane can never consume cleanup capacity. Cleanup uses the same
 * rate and concurrency controls, but receives priority once restoration starts.
 */
export class ScanRequestLedger {
  private readonly rateLimiter: RateLimiter;
  private readonly scanCapacity: number;
  private scanTransmitted = 0;
  private cleanupTransmitted = 0;
  private active = 0;
  private readonly waiting: Waiter[] = [];

  public constructor(
    private readonly maxRequests: number,
    private readonly cleanupReservedRequests: number,
    rateLimitPerSecond: number,
    private readonly concurrency: number,
    private readonly onUpdate?: ScanRequestLedgerUpdate
  ) {
    if (!Number.isInteger(maxRequests) || maxRequests < 1) throw new Error("SCAN_REQUEST_LEDGER_LIMIT_INVALID");
    if (!Number.isInteger(cleanupReservedRequests) || cleanupReservedRequests < 0 || cleanupReservedRequests > maxRequests) throw new Error("SCAN_CLEANUP_RESERVE_INVALID");
    if (!Number.isInteger(concurrency) || concurrency < 1) throw new Error("SCAN_REQUEST_LEDGER_CONCURRENCY_INVALID");
    this.scanCapacity = maxRequests - cleanupReservedRequests;
    this.rateLimiter = new RateLimiter(rateLimitPerSecond);
  }

  public snapshot(): ScanRequestLedgerSnapshot {
    return {
      maxRequests: this.maxRequests,
      cleanupReservedRequests: this.cleanupReservedRequests,
      scanCapacity: this.scanCapacity,
      scanTransmitted: this.scanTransmitted,
      cleanupTransmitted: this.cleanupTransmitted,
      totalTransmitted: this.scanTransmitted + this.cleanupTransmitted,
      scanRemaining: Math.max(0, this.scanCapacity - this.scanTransmitted),
      cleanupRemaining: Math.max(0, this.cleanupReservedRequests - this.cleanupTransmitted),
      inFlight: this.active,
      queued: this.waiting.length
    };
  }

  public hasCapacity(lane: RequestLedgerLane, count = 1): boolean {
    if (!Number.isInteger(count) || count < 1) return false;
    const snapshot = this.snapshot();
    return lane === "CLEANUP" ? snapshot.cleanupRemaining >= count : snapshot.scanRemaining >= count;
  }

  public tryReserve(lane: RequestLedgerLane): boolean {
    if (!this.hasCapacity(lane)) {
      this.publish(true);
      return false;
    }
    if (lane === "CLEANUP") this.cleanupTransmitted += 1;
    else this.scanTransmitted += 1;
    this.publish(true);
    return true;
  }

  public async waitForBurst(signal: AbortSignal | undefined, count: number): Promise<void> {
    await this.rateLimiter.wait(signal, count);
  }

  public async transmit<T>(
    lane: RequestLedgerLane,
    signal: AbortSignal | undefined,
    operation: () => Promise<T>,
    options: { rateAlreadyReserved?: boolean; onReserved?: () => void } = {}
  ): Promise<{ accepted: true; value: T } | { accepted: false }> {
    const release = await this.acquire(lane, signal);
    try {
      this.throwIfAborted(signal);
      if (!this.hasCapacity(lane)) {
        this.publish(true);
        return { accepted: false };
      }
      if (!options.rateAlreadyReserved) await this.rateLimiter.wait(signal);
      this.throwIfAborted(signal);
      if (!this.tryReserve(lane)) return { accepted: false };
      options.onReserved?.();
      return { accepted: true, value: await operation() };
    } finally {
      release();
    }
  }

  /** Applies the shared rate/concurrency gate to an externally transmitted
   * browser request whose budget was synchronously reserved during routing. */
  public async dispatchReserved<T>(lane: RequestLedgerLane, signal: AbortSignal | undefined, operation: () => Promise<T>): Promise<T> {
    const release = await this.acquire(lane, signal);
    try {
      await this.rateLimiter.wait(signal);
      this.throwIfAborted(signal);
      return await operation();
    } finally {
      release();
    }
  }

  private acquire(lane: RequestLedgerLane, signal?: AbortSignal): Promise<() => void> {
    this.throwIfAborted(signal);
    if (this.active < this.concurrency) {
      this.active += 1;
      this.publish();
      return Promise.resolve(this.releaseHandle());
    }
    return new Promise<() => void>((resolve, reject) => {
      const waiter: Waiter = { lane, resolve, reject, ...(signal ? { signal } : {}) };
      if (signal) {
        waiter.abort = () => {
          const index = this.waiting.indexOf(waiter);
          if (index >= 0) this.waiting.splice(index, 1);
          reject(new ScanCancelledError("Request dispatch was cancelled before transmission."));
          this.publish();
        };
        signal.addEventListener("abort", waiter.abort, { once: true });
      }
      this.waiting.push(waiter);
      this.publish();
    });
  }

  private releaseHandle(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const cleanupIndex = this.waiting.findIndex((item) => item.lane === "CLEANUP");
      const index = cleanupIndex >= 0 ? cleanupIndex : 0;
      const next = this.waiting.splice(index, 1)[0];
      if (next) {
        if (next.abort && next.signal) next.signal.removeEventListener("abort", next.abort);
        next.resolve(this.releaseHandle());
      } else {
        this.active -= 1;
      }
      this.publish();
    };
  }

  private throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) throw new ScanCancelledError();
  }

  private publish(budgetChanged = false): void {
    this.onUpdate?.(this.snapshot(), budgetChanged);
  }
}
