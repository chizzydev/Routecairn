import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, renameSync, linkSync, symlinkSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";
import { WorkerLifecycleEvidence, verifiedWorkerExit } from "../../src/dashboard/worker/WorkerLifecycleEvidence.js";

function lab(): string {
  // Adversarial aliases are retained separately from the ordinary journal root;
  // the normal global hook must never adopt them as its own clean inventory.
  const parent = process.env.ROUTECAIRN_WORKER_LAB ?? OwnedTemporaryResource.create(join(tmpdir(), "routecairn-adversarial-labs"), { purpose: "alias-refusal-fixture" }).root;
  const root = join(parent, "resource-" + randomUUID()); mkdirSync(root); return root;
}
describe("exclusive retained temporary resources", () => {
  it("requires matching attempt signatures and both voluntary-exit records", () => {
    const binding = { workerId: randomUUID(), generation: randomUUID(), jobId: randomUUID() }, r = OwnedTemporaryResource.create(lab(), binding), key = randomUUID();
    const writer = new WorkerLifecycleEvidence(r.directory("tmp"), r.workerProof(), binding, key);
    writer.record("PROCESS_EXIT_READY", "UNKNOWN"); expect(verifiedWorkerExit(r, key)).toBe(false);
    writer.record("PROCESS_EXIT", "UNKNOWN", 0); expect(verifiedWorkerExit(r, key)).toBe(true); expect(verifiedWorkerExit(r, "wrong-attempt-key")).toBe(false);
    expect(() => new WorkerLifecycleEvidence(r.directory("tmp"), r.workerProof(), { ...binding, generation: randomUUID() }, key)).toThrow("BINDING_INVALID");
  });
  it("permanently refuses worker evidence writes after marker uncertainty", () => {
    const binding = { workerId: randomUUID(), generation: randomUUID(), jobId: randomUUID() }, r = OwnedTemporaryResource.create(lab(), binding);
    const writer = new WorkerLifecycleEvidence(r.directory("tmp"), r.workerProof(), binding, randomUUID()), path = join(r.root, "OWNERSHIP.json"), bytes = readFileSync(path);
    writeFileSync(path, "CHANGED"); expect(() => writer.record("PROCESS_EXIT_READY", "UNKNOWN")).toThrow("MARKER_CHANGED");
    writeFileSync(path, bytes); expect(() => writer.record("PROCESS_EXIT", "UNKNOWN", 0)).toThrow("PERMANENT_REFUSAL");
  });
  it("keeps unrelated preexisting files and creates a unique capability", () => {
    const root = lab(); writeFileSync(join(root, "sentinel"), "OWNER_SENTINEL", { flag: "wx" });
    const a = OwnedTemporaryResource.create(root, { job: "a" }), b = OwnedTemporaryResource.create(root, { job: "b" });
    expect(a.root).not.toBe(b.root); expect(a.retain("DONE")).toMatchObject({ state: "RETAINED", inventoryComplete: true, deletionAuthorized: false });
    expect(readFileSync(join(root, "sentinel"), "utf8")).toBe("OWNER_SENTINEL");
  });
  it("permanently refuses a replaced child identity without deleting either tree", () => {
    const resource = OwnedTemporaryResource.create(lab(), { test: "replacement" }); const child = resource.directory("tmp");
    writeFileSync(join(child, "canary"), "RETAIN"); renameSync(child, child + "-retained"); mkdirSync(child);
    expect(() => resource.assertOwned()).toThrow("IDENTITY_CHANGED");
    expect(resource.retain("EXIT")).toMatchObject({ state: "UNKNOWN_RETAINED" });
    expect(() => resource.assertOwned()).toThrow("PERMANENT_REFUSAL"); expect(existsSync(join(child + "-retained", "canary"))).toBe(true);
  });
  it("rejects marker changes and never repairs or adopts them", () => {
    const resource = OwnedTemporaryResource.create(lab(), { test: "marker" }); const path = join(resource.root, "OWNERSHIP.json");
    const original = readFileSync(path); writeFileSync(path, "CHANGED");
    expect(resource.retain("EXIT")).toMatchObject({ state: "UNKNOWN_RETAINED", error: "TEMP_RESOURCE_MARKER_CHANGED" });
    writeFileSync(path, original); expect(() => resource.assertOwned()).toThrow("PERMANENT_REFUSAL");
  });
  it("refuses a junction container and never inventories its target", () => {
    const root = lab(), target = join(root, "target"), alias = join(root, "alias"); mkdirSync(target); symlinkSync(target, alias, "junction");
    expect(() => OwnedTemporaryResource.create(alias, { test: "alias" })).toThrow("ALIAS_REFUSED"); expect(existsSync(target)).toBe(true);
  });
  it("refuses hardlinked evidence while preserving both names", () => {
    const root = lab(), resource = OwnedTemporaryResource.create(root, { test: "hardlink" }); const outside = join(root, "outside"); writeFileSync(outside, "RETAIN"); linkSync(outside, join(resource.directory("tmp"), "linked"));
    expect(resource.retain("EXIT")).toMatchObject({ state: "UNKNOWN_RETAINED", inventoryComplete: false }); expect(readFileSync(outside, "utf8")).toBe("RETAIN");
  });
  it("bounds complete inventory and preserves overflow", () => {
    const resource = OwnedTemporaryResource.create(lab(), { test: "bounded" }), temp = resource.directory("tmp");
    for (let n = 0; n < 12; n++) writeFileSync(join(temp, String(n)), "DATA");
    expect(resource.retain("EXIT", 5)).toMatchObject({ state: "UNKNOWN_RETAINED", error: "TEMP_RESOURCE_INVENTORY_LIMIT", inventoryComplete: false }); expect(existsSync(join(temp, "11"))).toBe(true);
  });
  it("refuses child traversal without creating a path", () => { const r = OwnedTemporaryResource.create(lab(), {}); expect(() => r.directory("../escape")).toThrow("CHILD_INVALID"); });
});
