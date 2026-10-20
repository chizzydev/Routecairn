import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import { existsSync, readFileSync, appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { assertBrowserAccounting, assertTestAccounting, assertSafeExport, isLoopbackUrl } from "../../scripts/trusted-discovery-d0-policy.mjs";

let receipts = 0;
const target = createServer((_request, response) => { receipts++; response.end("disposable acceptance canary"); });
beforeAll(async () => { await new Promise<void>((done) => target.listen(0, "127.0.0.1", done)); });
afterAll(async () => {
  expect(receipts).toBe(0);
  if (process.env.ROUTECAIRN_D0_PROOF) appendFileSync(process.env.ROUTECAIRN_D0_PROOF, JSON.stringify({ phase: "policy-unit", os: process.platform, targetReceipts: receipts, timestamp: new Date().toISOString() }) + "\n");
  await new Promise<void>((done) => target.close(() => done()));
});
describe("D0 executable acceptance contract", () => {
  it("RED01 requires a real machine/source-bound portable acceptance probe", () => {
    const script = resolve("scripts/trusted-discovery-d0.mjs");
    const run = existsSync(script) ? spawnSync(process.execPath, [script, "--probe"], { encoding: "utf8", windowsHide: true }) : undefined;
    const result = run?.status === 0 ? JSON.parse(run.stdout) : { schemaVersion: 0, status: "MISSING_ACCEPTANCE_HARNESS" };
    expect(result.schemaVersion, "D0 machine-bound acceptance harness is absent").toBe(1);
    expect(result.machine.platform).toBe(process.platform);
    expect(result.sourceHead).toBe("8192cda2b8475306ecbec215f7c3623d74af25ee");
    expect(result.productExecution).toBe("UNREGISTERED");
  });
  it("RED02 requires fixed per-file lower bounds and16 explicit gates without hidden skips", () => {
    const path = resolve("tests/acceptance/trusted-discovery-d0-inventory.json");
    const inventory = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : { schemaVersion: 0, status: "MISSING_FIXED_GATE_INVENTORY" };
    expect(inventory.schemaVersion, "D0 fixed acceptance inventory is absent").toBe(1);
    expect(Object.keys(inventory.protectedTests)).toHaveLength(13);
    expect(Object.values(inventory.protectedTests).reduce((a: number, b) => a + Number(b), 0)).toBe(341);
    expect(inventory.gates).toHaveLength(16);
    expect(inventory.remainingStages).toEqual(["D1", "D2", "D3", "D4"]);
    expect(receipts).toBe(0);
  });
});
describe("D0 no hidden partial acceptance", () => {
  const sample = () => ({ success: true, numPendingTests: 0, numFailedTests: 0, numPassedTests: 1, numTotalTests: 1, testResults: [{ name: "/repo/required.test.ts", status: "passed", assertionResults: [{ status: "passed" }] }] });
  it("accepts complete exact required-file accounting", () => { expect(assertTestAccounting(sample(), { "required.test.ts": 1 }, 1)).toEqual({ tests: 1, files: 1, failed: 0, skipped: 0 }); });
  it.each(["missing-file", "lower-count", "skipped", "total-mismatch", "failed-file"])("refuses partial or fabricated accounting%s", (attack) => {
    const data = sample(); const required = attack === "missing-file" ? { "another.test.ts": 1 } : { "required.test.ts": attack === "lower-count" ? 2 : 1 };
    if (attack === "skipped") data.testResults[0]!.assertionResults[0]!.status = "pending";
    if (attack === "total-mismatch") { data.numTotalTests = 2; data.numPassedTests = 2; }
    if (attack === "failed-file") data.testResults[0]!.status = "failed";
    expect(() => assertTestAccounting(data, required)).toThrow(/D0_/);
  });
  it.each(["https://example.invalid", "http://127.0.0.1.evil.invalid", "http://owner:secret@127.0.0.1", "file:///tmp/report", "http://169.254.169.254"])("blocks non-fixture browser destinations%s", (value) => { expect(isLoopbackUrl(value)).toBe(false); });
  it("permits only literal owned loopback syntax before exact-origin allowlisting", () => { for (const value of ["http://127.0.0.1:1234", "https://[::1]:1234", "http://localhost:1234"]) expect(isLoopbackUrl(value)).toBe(true); });
  it("does not count a blocked browser case as PASS", () => {
    const result = { realBrowser: true, browserVersion: "149.0.7827.55", cleanup: "CONFIRMED", targetReceipts: 0, nonLoopbackTransmissions: 0, cases: [{ id: "B01", status: "BLOCKED" }] };
    expect(assertBrowserAccounting(result, ["B01"])).toMatchObject({ status: "HOLD", passed: 0, blocked: 1 });
    expect(() => assertBrowserAccounting({ ...result, cases: [] }, ["B01"])).toThrow();
    expect(() => assertBrowserAccounting({ ...result, targetReceipts: 1 }, ["B01"])).toThrow();
    expect(() => assertBrowserAccounting({ ...result, realBrowser: false }, ["B01"])).toThrow();
  });
  it("rejects private material and oversized exports instead of redacting failures into passes", () => {
    expect(() => assertSafeExport("fixture-password-123", ["fixture-password-123"])).toThrow();
    expect(() => assertSafeExport("BEGIN PRIVATE KEY")).toThrow();
    expect(() => assertSafeExport("routecairn_session=canary")).toThrow();
    expect(() => assertSafeExport("x".repeat(256 * 1024 + 1))).toThrow();
    expect(assertSafeExport("No HTTP GET was sent.")).toMatch(/^[a-f0-9]{64}$/);
  });
});
