import { sleep } from "./RateLimiter.js";
import type { RetryPolicyOptions } from "./HttpTypes.js";

export class RetryPolicy {
  public constructor(private readonly options: RetryPolicyOptions) {}

  public async run<T extends { statusCode?: number; error?: unknown }>(task: (attempt: number) => Promise<T>): Promise<T> {
    let lastResult: T | undefined;

    for (let attempt = 1; attempt <= this.options.maxAttempts; attempt += 1) {
      const result = await task(attempt);
      lastResult = result;

      if (!this.shouldRetry(result, attempt)) {
        return result;
      }

      await sleep(this.delayForAttempt(attempt));
    }

    return lastResult as T;
  }

  private shouldRetry(result: { statusCode?: number; error?: unknown }, attempt: number): boolean {
    if (attempt >= this.options.maxAttempts) {
      return false;
    }

    if (result.error) {
      if (isNonRetriableError(result.error)) {
        return false;
      }
      return true;
    }

    return typeof result.statusCode === "number" && this.options.retryStatusCodes.includes(result.statusCode);
  }

  private delayForAttempt(attempt: number): number {
    return Math.min(this.options.baseDelayMs * 2 ** (attempt - 1), this.options.maxDelayMs);
  }
}

function isNonRetriableError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "name" in error && error.name === "RequestBudgetExceeded";
}
