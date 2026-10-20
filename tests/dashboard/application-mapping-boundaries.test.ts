import { it, expect, vi } from "vitest";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { applicationMappingInputSchema } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
import { assertAuthorizationWorkbenchBinding } from "../../src/dashboard/execution/AuthorizationWorkbenchBinding.js";
import type { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { randomUUID } from "node:crypto";
it("refuses unsafe acquisition declarations, foreign bindings, oversized scope and missing identity with zero wire traffic", async () => {
  const f = await applicationMappingFixture();
  try {
    const input = f.mappingInput;
    for (const change of [
      { readOnlyRoutesConfirmed: false },
      { identityContextConfirmed: false },
      { routes: Array.from({ length: 9 }, () => input.routes[0]) },
      { routes: [{ ...input.routes[0], method: "POST" }] },
      { routes: [{ ...input.routes[0], identityPath: "password" }] },
      { routes: [{ ...input.routes[0], identityPath: "__proto__.id" }] }
    ])
      expect(applicationMappingInputSchema.safeParse({ ...input, ...change }).success).toBe(false);
    for (const url of [
      "https://example.test/api/documents/doc-a",
      f.origin + "/api/documents/doc-a?token=secret",
      f.origin + "/api/documents/%64oc-a",
      f.origin + "/api/unknown/doc-a",
      f.origin + "/api/documents/doc-a#fragment"
    ]) {
      await expect(f.mapping.preview(f.org, { ...input, routes: [{ ...input.routes[0], url }] })).rejects.toThrow(
        "EXACT_SCOPED_ROUTE"
      );
    }
    await expect(f.mapping.preview(f.org, { ...input, routes: [input.routes[0], input.routes[0]] })).rejects.toThrow(
      "EXACT_SCOPED_ROUTE"
    );
    await expect(
      f.mapping.preview(f.org, {
        ...input,
        credentials: { ...input.credentials, account_b: input.credentials.primary }
      })
    ).rejects.toThrow("DISTINCT_ACTORS");
    await expect(f.mapping.preview(randomUUID(), input)).rejects.toThrow("OWNED_LOOPBACK");
    f.database.db.prepare("UPDATE credential_profiles SET enabled=0 WHERE id=?").run(input.credentials.account_b);
    await expect(f.mapping.preview(f.org, input)).rejects.toThrow("CREDENTIAL_BINDING");
    expect(f.wire).toHaveLength(0);
    f.capture("GUIDED_DECLARATIVE_REFUSALS_NO_WIRE");
  } finally {
    await f.close();
  }
});
it("binds target, credential, exact request and expiry while keeping immutable acquisition history", async () => {
  const f = await applicationMappingFixture();
  try {
    const one = await f.mapping.create(f.org, f.mappingInput, "operator");
    f.database.db
      .prepare("INSERT INTO application_mapping_dispatches VALUES(?,?,?)")
      .run(one.revisionId, "operator", new Date().toISOString());
    expect(() =>
      assertAuthorizationWorkbenchBinding(f.database, {
        ...one.request,
        applicationMappingBinding: { revisionId: one.revisionId, digest: one.digest },
        maxRequests: 41
      })
    ).toThrow("REQUEST_CHANGED");
    expect(() =>
      f.database.db.prepare("UPDATE application_mapping_revisions SET digest='x' WHERE id=?").run(one.revisionId)
    ).toThrow("IMMUTABLE_MAPPING");
    expect(() =>
      f.database.db.prepare("DELETE FROM application_mapping_dispatches WHERE revision_id=?").run(one.revisionId)
    ).toThrow("IMMUTABLE_MAPPING");
    const two = await f.mapping.create(f.org, f.mappingInput, "operator");
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.mappingInput.targetId);
    await expect(f.mapping.execute(f.org, two.revisionId, two.digest, "operator")).rejects.toThrow("BINDINGS_CHANGED");
    const three = await f.mapping.create(f.org, f.mappingInput, "operator");
    f.database.db
      .prepare("UPDATE credential_profiles SET secret_version=secret_version+1 WHERE id=?")
      .run(f.mappingInput.credentials.account_a);
    await expect(f.mapping.execute(f.org, three.revisionId, three.digest, "operator")).rejects.toThrow(
      "BINDINGS_CHANGED"
    );
    const four = await f.mapping.create(f.org, f.mappingInput, "operator");
    await f.execution.shutdown();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      await expect(f.mapping.execute(f.org, four.revisionId, four.digest, "operator")).rejects.toThrow("STALE_REVIEW");
      expect((await f.mapping.execute(f.org, one.revisionId, one.digest, "operator")).status).toBe("UNKNOWN");
    } finally {
      vi.useRealTimers();
    }
    expect(f.wire).toHaveLength(0);
    f.capture("GUIDED_IMMUTABLE_STALE_NO_WIRE");
  } finally {
    await f.close();
  }
});
it("revalidates acquisition binding at actual native JOB_ACCEPTED before credential delivery or HTTP", async () => {
  const f = await applicationMappingFixture();
  try {
    const revision = await f.mapping.create(f.org, f.mappingInput, "operator"),
      workers = (f.execution as unknown as { workers: ScanWorkerManager }).workers,
      run = workers.run.bind(workers);
    workers.run = (...args: Parameters<ScanWorkerManager["run"]>) => {
      f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.mappingInput.targetId);
      return run(...args);
    };
    const result = await f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator");
    await expect(f.wait(result.scanId!)).rejects.toThrow(
      "FIXTURE_NATIVE_SCAN_INTERRUPTED:WORKBENCH_MAPPING_BINDINGS_CHANGED"
    );
    expect(f.mapping.result(f.org, revision.revisionId)).toMatchObject({
      status: "INTERRUPTED",
      failureReason: expect.stringContaining("BINDINGS_CHANGED")
    });
    expect(f.wire).toHaveLength(0);
    expect(f.status(result.scanId!).error_summary).toContain("BINDINGS_CHANGED");
    f.capture("GUIDED_NATIVE_BOOTSTRAP_FENCE");
  } finally {
    await f.close();
  }
});
it("consumes concurrent observation authorization once and reads its acknowledgement after expiry without another native scan", async () => {
  const f = await applicationMappingFixture();
  try {
    const revision = await f.mapping.create(f.org, f.mappingInput, "operator"),
      runs = await Promise.allSettled([
        f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator"),
        f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator")
      ]);
    const accepted = runs.find((r) => r.status === "fulfilled");
    if (accepted?.status !== "fulfilled") throw Error("No native acceptance");
    await f.wait(accepted.value.scanId!);
    expect(f.wire).toHaveLength(20);
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM scans").get()).toEqual({ n: 1 });
    await f.execution.shutdown();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      expect(await f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator")).toMatchObject({
        scanId: accepted.value.scanId,
        status: "ALREADY_RECORDED",
        replayed: false
      });
      await expect(f.mapping.execute(f.org, revision.revisionId, revision.digest, "other")).rejects.toThrow(
        "CONSUMED_BY_ANOTHER"
      );
    } finally {
      vi.useRealTimers();
    }
    expect(f.wire).toHaveLength(20);
    f.capture("GUIDED_CONCURRENT_NATIVE_SINGLE_DISPATCH");
  } finally {
    await f.close();
  }
});
it("keeps lost native enqueue acknowledgements UNKNOWN durably and never replays even after expiry", async () => {
  const f = await applicationMappingFixture();
  try {
    const revision = await f.mapping.create(f.org, f.mappingInput, "operator");
    f.database.db.exec(
      "CREATE TRIGGER fixture_mapping_ack_failure BEFORE INSERT ON application_mapping_acknowledgements BEGIN SELECT RAISE(ABORT,'FIXTURE_ACK_UNAVAILABLE'); END"
    );
    await expect(f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator")).rejects.toThrow(
      "FIXTURE_ACK_UNAVAILABLE"
    );
    const scan = f.database.db.prepare("SELECT id FROM scans").get() as { id: string };
    await f.wait(scan.id);
    await f.execution.shutdown();
    expect(f.mapping.result(f.org, revision.revisionId).status).toBe("UNKNOWN");
    const count = f.wire.length;
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      expect(await f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator")).toMatchObject({
        status: "UNKNOWN",
        scanId: null,
        replayed: false
      });
    } finally {
      vi.useRealTimers();
    }
    expect(f.wire).toHaveLength(count);
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM scans").get()).toEqual({ n: 1 });
    f.capture("GUIDED_LOST_ACK_UNKNOWN_NO_REPLAY");
  } finally {
    await f.close();
  }
});
it("requires actual observed ALLOW marker proof, retaining missing controls and wrong declared objects as unbound", async () => {
  const f = await applicationMappingFixture();
  try {
    f.setMissingAllowControl();
    const a = await f.acquire(),
      wire = f.wire.length;
    const missing = await f.mapping.createMatrix(f.org, a.revision.revisionId, f.policy, "operator");
    expect(missing.classification).toBe("REQUIRES_BINDINGS");
    expect(missing.blockers).toContain("MAPPING_ALLOW_CONTROL_MARKER_NOT_OBSERVED:document:primary");
    await expect(f.service.execute(f.org, missing.revisionId, missing.digest, "operator")).rejects.toThrow(
      "BINDINGS_CHANGED"
    );
    const wrong = structuredClone(f.policy);
    wrong.expectations[1]!.identity!.expectedValue = "not-observed";
    const blocked = await f.mapping.createMatrix(f.org, a.revision.revisionId, wrong, "operator");
    expect(blocked.blockers).toContain("MAPPING_ALLOW_CONTROL_MARKER_NOT_OBSERVED:secure:primary");
    expect(blocked.matrix.every((c) => c.status === "REQUIRES_BINDINGS")).toBe(true);
    const wrongTenant = structuredClone(f.policy);
    wrongTenant.expectations[3]!.tenant!.expectedValue = "wrong-tenant";
    const functionBlocked = await f.mapping.createMatrix(f.org, a.revision.revisionId, wrongTenant, "operator");
    expect(functionBlocked.blockers).toContain("MAPPING_ALLOW_CONTROL_MARKER_NOT_OBSERVED:admin:primary");
    expect(f.wire).toHaveLength(wire);
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM scans").get()).toEqual({ n: 1 });
    f.capture("GUIDED_MISSING_ALLOW_CONTROL_ABSTENTION");
  } finally {
    await f.close();
  }
});
