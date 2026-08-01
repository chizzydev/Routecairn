export class RequestQueue {
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  public constructor(private readonly concurrency: number) {}

  public async run<T>(task: () => Promise<T>): Promise<T> {
    await this.acquire();

    try {
      return await task();
    } finally {
      this.release();
    }
  }

  private async acquire(): Promise<void> {
    if (this.active < this.concurrency) {
      this.active += 1;
      return;
    }

    await new Promise<void>((resolve) => {
      this.waiting.push(resolve);
    });
  }

  private release(): void {
    const next = this.waiting.shift();

    if (next) {
      next();
      return;
    }

    this.active -= 1;
  }
}
