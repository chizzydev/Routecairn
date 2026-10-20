import { it, expect } from "vitest";
import { authorizationWorkbenchFixture } from "../helpers/authorization-workbench-fixture.js";
it("runs the complete IR-backed matrix and proves vulnerable, secure, near-miss, isolated actors and remediation through native Windows workers", async () => {
  const f = await authorizationWorkbenchFixture();
  try {
    const old = await f.service.create(f.org, f.input, "fixture-owner");
    expect(old.blockers).toEqual([]);
    expect(old.transportIntents).toHaveLength(20);
    expect(old.transportIntents.filter((i) => i.purpose === "VERIFY_PRINCIPAL_TENANT_ROLE")).toHaveLength(3);
    expect(old.transportIntents.every((i) => new URL(i.url).origin === f.origin)).toBe(true);
    expect(old.provenance.observations.observations.length).toBeGreaterThan(0);
    expect(old.provenance.attackGraph!.nodes.some((n) => n.kind === "TENANT")).toBe(true);
    expect(old.matrix.every((c) => c.securityCaseIds.length > 0)).toBe(true);
    const first = await f.service.execute(f.org, old.revisionId, old.digest, "fixture-owner");
    await f.wait(first.scanId!);
    const before = f.service.result(f.org, old.revisionId);
    expect(before.status).toBe("FINDINGS");
    if (!("checks" in before)) throw Error("Expected executed evidence");
    expect(before.checks.filter((c) => c.checkId.startsWith("document-") && c.outcome === "FAIL")).toHaveLength(2);
    expect(before.checks.filter((c) => c.checkId.startsWith("secure-")).every((c) => c.outcome === "PASS")).toBe(true);
    expect(
      before.checks
        .filter((c) => c.checkId.startsWith("masked-") && ["member", "outsider"].some((a) => c.checkId.endsWith(a)))
        .every((c) => c.outcome === "INCONCLUSIVE")
    ).toBe(true);
    expect(before.findings).toHaveLength(2);
    expect(before.checks.filter((c) => c.checkId.startsWith("admin-")).every((c) => c.outcome === "PASS")).toBe(true);
    const count = f.wire.length;
    expect((await f.service.execute(f.org, old.revisionId, old.digest, "fixture-owner")).status).toBe(
      "ALREADY_RECORDED"
    );
    expect(f.wire).toHaveLength(count);
    f.setFixed();
    const next = await f.service.create(f.org, f.input, "fixture-owner"),
      second = await f.service.execute(f.org, next.revisionId, next.digest, "fixture-owner");
    await f.wait(second.scanId!);
    const after = f.service.result(f.org, next.revisionId);
    expect(after.status).toBe("INCONCLUSIVE");
    if (!("findings" in after)) throw Error("Expected report");
    expect(after.findings).toEqual([]);
    expect(f.service.result(f.org, old.revisionId)).toEqual(before);
    expect(f.wire.every((w) => w.method === "GET")).toBe(true);
    expect(new Set(f.wire.filter((w) => w.path === "/identity").map((w) => w.actor))).toEqual(
      new Set(["owner", "member", "outsider"])
    );
    f.capture("NATIVE_BEFORE_AFTER_ACCEPTANCE");
  } finally {
    await f.close();
  }
});
