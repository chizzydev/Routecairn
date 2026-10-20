import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { it, expect, vi } from "vitest";
import { authorizationWorkbenchFixture } from "../helpers/authorization-workbench-fixture.js";
import { authorizationWorkbenchInputSchema } from "../../src/dashboard/contracts/AuthorizationWorkbenchContracts.js";
import { assertAuthorizationWorkbenchBinding } from "../../src/dashboard/execution/AuthorizationWorkbenchBinding.js";
import { randomUUID } from "node:crypto";
import type { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
it("refuses missing proof, mutations, foreign scope, stale targets/credentials and edited plans without target traffic", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    await f.execution.shutdown();
    const initial = f.wire.length,
      unknown = structuredClone(f.input);
    unknown.expectations[0]!.decisions.outsider = "UNKNOWN";
    const incomplete = await f.service.create(f.org, unknown, "operator");
    expect(incomplete.classification).toBe("REQUIRES_BINDINGS");
    await expect(f.service.execute(f.org, incomplete.revisionId, incomplete.digest, "operator")).rejects.toThrow(
      "BINDINGS_CHANGED"
    );
    const noUrl = structuredClone(f.input);
    delete noUrl.expectations[0]!.url;
    expect((await f.service.preview(f.org, noUrl)).blockers).toContain(
      "EXACT_OBSERVED_TEMPLATE_URL_BINDING_REQUIRED:document"
    );
    expect(authorizationWorkbenchInputSchema.safeParse({ ...f.input, method: "POST" }).success).toBe(false);
    const foreign = structuredClone(f.input);
    foreign.expectations[0]!.url = "https://example.test/api/documents/doc-a";
    expect((await f.service.preview(f.org, foreign)).classification).toBe("REQUIRES_BINDINGS");
    const mismatched = structuredClone(f.input);
    mismatched.credentials.account_b = mismatched.credentials.primary;
    expect(
      (await f.service.preview(f.org, mismatched)).blockers.some((b) => b.startsWith("ACTOR_CONTEXT_UNVERIFIED"))
    ).toBe(true);
    const revision = await f.service.create(f.org, f.input, "operator");
    expect(() => f.service.row(randomUUID(), revision.revisionId)).toThrow("NOT_FOUND");
    f.database.db
      .prepare("INSERT INTO authorization_workbench_dispatches VALUES(?,?,?)")
      .run(revision.revisionId, "operator", new Date().toISOString());
    const altered = {
      ...revision.request,
      authorizationWorkbenchBinding: { revisionId: revision.revisionId, digest: revision.digest },
      maxRequests: 41
    };
    expect(() => assertAuthorizationWorkbenchBinding(f.database, altered)).toThrow("REQUEST_CHANGED");
    const r2 = await f.service.create(f.org, f.input, "operator");
    f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.input.targetId);
    await expect(f.service.execute(f.org, r2.revisionId, r2.digest, "operator")).rejects.toThrow("BINDINGS_CHANGED");
    const r3 = await f.service.create(f.org, f.input, "operator");
    f.database.db
      .prepare("UPDATE credential_profiles SET secret_version=secret_version+1 WHERE id=?")
      .run(f.input.credentials.account_b);
    await expect(f.service.execute(f.org, r3.revisionId, r3.digest, "operator")).rejects.toThrow("BINDINGS_CHANGED");
    expect(f.wire).toHaveLength(initial);
    expect(() =>
      f.database.db
        .prepare("UPDATE authorization_workbench_revisions SET digest='forged' WHERE id=?")
        .run(revision.revisionId)
    ).toThrow("IMMUTABLE");
    expect(() =>
      f.database.db
        .prepare("DELETE FROM authorization_workbench_dispatches WHERE revision_id=?")
        .run(revision.revisionId)
    ).toThrow("IMMUTABLE");
    expect((await f.service.execute(f.org, revision.revisionId, revision.digest, "operator")).status).toBe("UNKNOWN");
    const expiring = await f.service.create(f.org, f.input, "operator");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 600001);
      await expect(f.service.execute(f.org, expiring.revisionId, expiring.digest, "operator")).rejects.toThrow(
        "STALE_REVIEW"
      );
    } finally {
      vi.useRealTimers();
    }
    const artifact = f.database.db
      .prepare("SELECT a.canonical_path FROM scans s JOIN artifacts a ON a.id=s.json_report_artifact_id WHERE s.id=?")
      .get(f.sourceScanId) as { canonical_path: string };
    const original = readFileSync(artifact.canonical_path);
    writeFileSync(join(f.root, "SOURCE_REPORT_BEFORE_TAMPER.json"), original, { flag: "wx" });
    writeFileSync(artifact.canonical_path, Buffer.concat([original, Buffer.from(" ")]));
    await expect(f.service.preview(f.org, f.input)).rejects.toThrow("OBSERVATION_CHANGED");
    expect(f.wire).toHaveLength(initial);
    f.capture("BOUNDARY_REFUSALS_NO_WIRE");
  } finally {
    await f.close();
  }
});
it("rechecks bound metadata at the native bootstrap boundary before any HTTP or credential delivery", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    const revision = await f.service.create(f.org, f.input, "operator"),
      count = f.wire.length;
    const workers = (f.execution as unknown as { workers: ScanWorkerManager }).workers,
      run = workers.run.bind(workers);
    workers.run = (...args: Parameters<ScanWorkerManager["run"]>) => {
      f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.input.targetId);
      return run(...args);
    };
    const result = await f.service.execute(f.org, revision.revisionId, revision.digest, "operator");
    const end = Date.now() + 15000;
    while (Date.now() < end && !["FAILED", "INTERRUPTED"].includes(f.status(result.scanId!).status))
      await new Promise((r) => setTimeout(r, 50));
    expect(["FAILED", "INTERRUPTED"]).toContain(f.status(result.scanId!).status);
    expect(f.status(result.scanId!).error_summary).toContain("WORKBENCH_BINDINGS_CHANGED");
    expect(f.wire).toHaveLength(count);
    f.capture("NATIVE_BOOTSTRAP_BINDING_REFUSAL");
  } finally {
    await f.close();
  }
});
it("retains a durable UNKNOWN after a lost enqueue acknowledgement and never replays the revision", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    const revision = await f.service.create(f.org, f.input, "operator");
    f.database.db.exec(
      "CREATE TRIGGER fixture_ack_failure BEFORE INSERT ON authorization_workbench_acknowledgements BEGIN SELECT RAISE(ABORT,'FIXTURE_ACK_FAILURE'); END"
    );
    await expect(f.service.execute(f.org, revision.revisionId, revision.digest, "operator")).rejects.toThrow(
      "FIXTURE_ACK_FAILURE"
    );
    const scan = f.database.db
      .prepare("SELECT id FROM scans WHERE id<>? ORDER BY created_at DESC LIMIT 1")
      .get(f.sourceScanId) as { id: string };
    await f.wait(scan.id);
    const count = f.wire.length;
    expect((await f.service.execute(f.org, revision.revisionId, revision.digest, "operator")).status).toBe("UNKNOWN");
    expect(f.service.result(f.org, revision.revisionId).status).toBe("UNKNOWN");
    expect(f.wire).toHaveLength(count);
    f.capture("LOST_ACK_UNKNOWN_NO_REPLAY");
  } finally {
    await f.close();
  }
});

it("consumes one revision under concurrent submissions and returns its recorded scan without another dispatch", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    const r = await f.service.create(f.org, f.input, "operator"),
      results = await Promise.allSettled([
        f.service.execute(f.org, r.revisionId, r.digest, "operator"),
        f.service.execute(f.org, r.revisionId, r.digest, "operator")
      ]);
    expect(results.some((r) => r.status === "fulfilled")).toBe(true);
    const rows = f.database.db
      .prepare("SELECT scan_id FROM authorization_workbench_acknowledgements WHERE revision_id=?")
      .all(r.revisionId) as { scan_id: string }[];
    expect(rows).toHaveLength(1);
    await f.wait(rows[0]!.scan_id);
    const n = f.wire.length;
    expect((await f.service.execute(f.org, r.revisionId, r.digest, "operator")).scanId).toBe(rows[0]!.scan_id);
    expect(f.wire).toHaveLength(n);
    expect(f.database.db.prepare("SELECT id FROM scans WHERE id<>?").all(f.sourceScanId)).toHaveLength(1);
    f.capture("CONCURRENT_SINGLE_NATIVE_DISPATCH");
  } finally {
    await f.close();
  }
});
