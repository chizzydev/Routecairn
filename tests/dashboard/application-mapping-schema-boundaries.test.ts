import { it, expect, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
import { assertApplicationMappingBinding } from "../../src/dashboard/execution/ApplicationMappingBinding.js";
import type { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
it("keeps schema scope, concrete slots, revision and authority bindings inert and immutable", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { schema, mappingInput: i } = f.makeInput();
    for (const b of [
      { ...i.schemaBinding!, digest: "0".repeat(64) },
      { ...i.schemaBinding!, revisionId: randomUUID() },
      { ...i.schemaBinding!, selections: [] },
      {
        ...i.schemaBinding!,
        selections: i.schemaBinding!.selections.map((s, n) => (n === 0 ? { ...s, slots: { number: "../42" } } : s))
      }
    ])
      await expect(f.mapping.preview(f.org, { ...i, schemaBinding: b })).rejects.toThrow();
    await expect(f.mapping.preview(randomUUID(), i)).rejects.toThrow();
    await expect(
      f.mapping.preview(f.org, {
        ...i,
        routes: i.routes.map((r, n) => (n === 0 ? { ...r, url: f.origin + "/v2/records/73" } : r))
      })
    ).rejects.toThrow("EXACT_SELECTION");
    expect(() => f.schemaService.result(randomUUID(), schema.revisionId)).toThrow("NOT_FOUND");
    expect(() =>
      f.database.db
        .prepare("UPDATE application_schema_revisions SET summary_json='{}' WHERE id=?")
        .run(schema.revisionId)
    ).toThrow("IMMUTABLE_SCHEMA");
    const review = await f.mapping.create(f.org, i, "operator");
    const different = f.schemaService.create(
      f.org,
      { targetId: f.targetId, document: f.document.replace('"3.1.0"', '"3.0.3"') },
      "operator"
    );
    expect(different.digest).not.toBe(schema.digest);
    expect(f.mapping.result(f.org, review.revisionId).input.schemaBinding?.revisionId).toBe(schema.revisionId);
    f.database.db
      .prepare("INSERT INTO application_mapping_dispatches VALUES(?,?,?)")
      .run(review.revisionId, "operator", new Date().toISOString());
    expect(() =>
      assertApplicationMappingBinding(f.database, {
        ...review.request,
        maxRequests: 41,
        applicationMappingBinding: { revisionId: review.revisionId, digest: review.digest }
      })
    ).toThrow("REQUEST_CHANGED");
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.targetId);
    await expect(f.mapping.preview(f.org, i)).rejects.toThrow("SCHEMA_BINDINGS_CHANGED");
    expect(f.wire).toHaveLength(0);
    f.capture("SCHEMA_NO_WIRE_BOUNDARIES");
  } finally {
    await f.close();
  }
});
it("refuses stale schema-bound observation before dispatch without extending original expiry", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { mappingInput } = f.makeInput(),
      r = await f.mapping.create(f.org, mappingInput, "operator");
    await f.execution.shutdown();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      await expect(f.mapping.execute(f.org, r.revisionId, r.digest, "operator")).rejects.toThrow("STALE_REVIEW");
    } finally {
      vi.useRealTimers();
    }
    expect(f.wire).toEqual([]);
  } finally {
    await f.close();
  }
});
it("consumes concurrent schema-bound approvals only once with actual native worker evidence", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { mappingInput } = f.makeInput(),
      r = await f.mapping.create(f.org, mappingInput, "operator"),
      runs = await Promise.allSettled([
        f.mapping.execute(f.org, r.revisionId, r.digest, "operator"),
        f.mapping.execute(f.org, r.revisionId, r.digest, "operator")
      ]);
    const accepted = runs.find((r) => r.status === "fulfilled");
    if (accepted?.status !== "fulfilled") throw Error("No acceptance");
    await f.wait(accepted.value.scanId!);
    expect(f.wire).toHaveLength(20);
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM scans").get()).toEqual({ n: 1 });
    f.capture("SCHEMA_CONCURRENT_NATIVE");
  } finally {
    await f.close();
  }
});
it("retains interrupted schema acquisition and refuses comparison after authority drift without another dispatch", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { mappingInput } = f.makeInput(),
      r = await f.mapping.create(f.org, mappingInput, "operator"),
      workers = (f.execution as unknown as { workers: ScanWorkerManager }).workers,
      run = workers.run.bind(workers);
    workers.run = (...args: Parameters<ScanWorkerManager["run"]>) => {
      f.database.db
        .prepare("UPDATE credential_profiles SET secret_version=secret_version+1 WHERE id=?")
        .run(f.credentials.primary);
      return run(...args);
    };
    const a = await f.mapping.execute(f.org, r.revisionId, r.digest, "operator");
    await expect(f.wait(a.scanId!)).rejects.toThrow("INTERRUPTED");
    expect(f.mapping.result(f.org, r.revisionId).status).toBe("INTERRUPTED");
    expect(f.wire).toHaveLength(0);
    await expect(f.mapping.execute(f.org, r.revisionId, r.digest, "other")).rejects.toThrow("CONSUMED");
    expect(() =>
      f.comparisons.create(f.org, { baselineRevisionId: r.revisionId, currentRevisionId: r.revisionId }, "operator")
    ).toThrow();
    f.capture("SCHEMA_NATIVE_IDENTITY_FENCE");
  } finally {
    await f.close();
  }
});
it.each(["wrong-primary", "identity-spoof", "missing-control"])(
  "does not turn %s into authorization proof",
  async (fault) => {
    const f = await schemaApplicationFixture();
    try {
      const { mappingInput } = f.makeInput();
      if (fault === "wrong-primary") f.setWrongPrimary();
      if (fault === "identity-spoof") f.setIdentitySpoof();
      if (fault === "missing-control") f.setMissingControl();
      const r = await f.mapping.create(f.org, mappingInput, "operator"),
        a = await f.mapping.execute(f.org, r.revisionId, r.digest, "operator");
      await f.wait(a.scanId!);
      const count = f.wire.length,
        proof = await f.mapping.createMatrix(f.org, r.revisionId, f.policyFor(mappingInput), "operator");
      expect(proof.blockers.some((b) => b.includes("ALLOW_CONTROL"))).toBe(true);
      expect(proof.classification).toBe("REQUIRES_BINDINGS");
      expect(f.wire).toHaveLength(count);
      f.capture("SCHEMA_NATIVE_FAULT_" + fault);
    } finally {
      await f.close();
    }
  }
);
