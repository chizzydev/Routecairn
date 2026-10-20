import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { collectionApplicationFixture } from "../helpers/collection-application-fixture.js";
import { hypothesisSource } from "../../src/dashboard/execution/ApplicationHypothesisBinding.js";
import { readCollectionObservation } from "../../src/dashboard/execution/CollectionMappingEvidence.js";
import { ApplicationMapComparisonService } from "../../src/dashboard/execution/ApplicationMapComparison.js";
it("rejects slot, actor, check, audit, body and source evidence substitutions", async () => {
  const f = await collectionApplicationFixture();
  try {
    const a = await f.acquire(),
      original = hypothesisSource(f.database, f.org, a.revision.revisionId),
      id = f.onboard.input.routes[0]!.id;
    expect(readCollectionObservation(original, id, "primary").valid).toBe(true);
    const faults = ["actor", "slot", "check", "route", "body", "audit", "credential"];
    for (const fault of faults) {
      const o = structuredClone(original),
        p = o.report!.scanPlan!.apiGraphql!,
        c = o.report!.apiGraphql!.checks[0]!;
      if (fault === "actor") p.actors[0]!.principalFingerprint = "a".repeat(16);
      if (fault === "slot") p.actors[0]!.authSlot = "account_b";
      if (fault === "check") c.comparisonFingerprint = "b".repeat(64);
      if (fault === "route") p.routes[0]!.urlFingerprint = "c".repeat(64);
      if (fault === "body") c.collection!.bodyFingerprint = "d".repeat(64);
      if (fault === "audit")
        o.report!.requestAudit = o.report!.requestAudit.filter((x) => x.requestId !== c.collection!.requestId);
      if (fault === "credential") {
        const saved = JSON.parse(o.row.request_json!);
        saved.credentialProfileId = randomUUID();
        o.row.request_json = JSON.stringify(saved);
      }
      expect(readCollectionObservation(o, id, "primary").valid, fault).toBe(false);
    }
    f.capture("COLLECTION_BINDING_FAULTS", {
      faults,
      original,
      scope: "Constructed report copies; immutable artifacts not rewritten"
    });
    const artifact = f.database.db
      .prepare("SELECT json_report_artifact_id id FROM scans WHERE id=?")
      .get(a.run.scanId) as { id: string };
    f.database.db
      .prepare("UPDATE artifacts SET scoped_or_full_safe_hash=? WHERE id=?")
      .run("e".repeat(64), artifact.id);
    expect(() => f.mapping.result(f.org, a.revision.revisionId)).toThrow("SOURCE_CHANGED");
    f.capture("COLLECTION_SOURCE_HASH_REFUSAL", { artifact, requests: f.wire.length });
  } finally {
    await f.close();
  }
});
it.each(["mode", "role", "credential"])(
  "refuses %s replacement after reviewed collection observation",
  async (kind) => {
    const f = await collectionApplicationFixture();
    try {
      f.setBehavior("late-foreign");
      const a = await f.acquire(),
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
        before = f.wire.length,
        id = f.onboard.credentials.primary,
        c = f.vault.getSummary(id, f.org)!;
      if (kind === "credential")
        f.vault.replaceSecret(id, {
          ...f.vault.decryptForHealthCheck(id),
          authorizationHeader: "Bearer generated-replacement"
        });
      else
        f.vault.updateMetadata(id, {
          organizationId: f.org,
          targetId: f.onboard.targetId,
          name: c.name,
          safeAlias: c.safeAlias,
          expiresAt: c.expiresAt,
          safeIdentitySummary: {
            ...c.safeIdentitySummary,
            ...(kind === "role"
              ? { role: "different-role" }
              : { identityModel: "TENANT_AWARE", tenantId: "generated-tenant" })
          }
        });
      expect(() => f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator")).toThrow(
        "AUTHORITY_CHANGED"
      );
      expect(f.hypotheses.get(f.org, p.proposalId).freshness).not.toBe("CURRENT");
      expect(f.wire.length).toBe(before);
      f.capture("COLLECTION_AUTHORITY_REFUSAL", { kind, requestsAfterChange: 0, history: p });
    } finally {
      await f.close();
    }
  }
);
it("immutable map comparison carries collection semantics and abstains for incomplete later results", async () => {
  const f = await collectionApplicationFixture();
  try {
    const a = await f.acquire();
    f.setBehavior("empty");
    const b = await f.acquire(),
      comparison = new ApplicationMapComparisonService(f.database).create(
        f.org,
        { baselineRevisionId: a.revision.revisionId, currentRevisionId: b.revision.revisionId },
        "operator"
      );
    expect(comparison.verifiedApplicationPass).toBe(false);
    expect(
      comparison.routes[0]!.cells.filter((c) => c.actorId !== "anonymous").every((c) => c.accessChange === "UNKNOWN")
    ).toBe(true);
    f.capture("COLLECTION_COMPARISON_UNKNOWN", comparison);
  } finally {
    await f.close();
  }
});
