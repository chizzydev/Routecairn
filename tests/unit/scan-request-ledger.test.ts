import { describe, expect, it } from "vitest";
import { ScanRequestLedger } from "../../src/core/http/ScanRequestLedger.js";

describe("ScanRequestLedger", () => {
  it("paces independent callers through one rate ledger", async () => {
    const ledger = new ScanRequestLedger(3, 0, 20, 3);
    const dispatched: number[] = [];
    await Promise.all(Array.from({ length: 3 }, () => ledger.transmit("SCAN", undefined, async () => {
      dispatched.push(Date.now());
      return true;
    })));
    expect(dispatched).toHaveLength(3);
    expect(dispatched[1]! - dispatched[0]!).toBeGreaterThanOrEqual(35);
    expect(dispatched[2]! - dispatched[1]!).toBeGreaterThanOrEqual(35);
  });

  it("prioritizes queued cleanup without allowing it to borrow scan capacity", async () => {
    const ledger = new ScanRequestLedger(4, 2, 100, 1);
    const order: string[] = [];
    let releaseFirst!: () => void;
    const held = new Promise<void>((resolve) => { releaseFirst = resolve; });
    const first = ledger.transmit("SCAN", undefined, async () => { order.push("first"); await held; return true; });
    await until(() => ledger.snapshot().inFlight === 1);
    const second = ledger.transmit("SCAN", undefined, async () => { order.push("second"); return true; });
    const cleanup = ledger.transmit("CLEANUP", undefined, async () => { order.push("cleanup"); return true; });
    await until(() => ledger.snapshot().queued === 2);
    releaseFirst();
    await Promise.all([first, second, cleanup]);
    expect(order).toEqual(["first", "cleanup", "second"]);
    expect(ledger.snapshot()).toMatchObject({ scanTransmitted: 2, cleanupTransmitted: 1, totalTransmitted: 3, scanRemaining: 0, cleanupRemaining: 1, inFlight: 0, queued: 0 });
  });
});

async function until(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error("Timed out waiting for ledger state.");
}
