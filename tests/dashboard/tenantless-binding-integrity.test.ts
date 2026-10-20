import { it, expect, vi } from "vitest";
import { randomUUID } from "node:crypto";
import { tenantlessApplicationFixture } from "../helpers/tenantless-application-fixture.js";
import { ApplicationAssessmentReadiness } from "../../src/dashboard/execution/ApplicationAssessmentReadiness.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
it("rejects expired, disabled, cross-org and cross-target profiles without requests or readiness decryption", async () => {
  const f = await tenantlessApplicationFixture();
  try {
    const id = f.onboard.credentials.primary,
      c = f.vault.getSummary(id, f.org)!,
      replace = (expiresAt: string) =>
        f.vault.updateMetadata(id, {
          name: c.name,
          safeAlias: c.safeAlias,
          targetId: f.onboard.targetId,
          organizationId: f.org,
          expiresAt,
          safeIdentitySummary: c.safeIdentitySummary
        });
    const spy = vi.spyOn(f.vault, "decryptForHealthCheck");
    replace("2000-01-01T00:00:00Z");
    expect(
      new ApplicationAssessmentReadiness(f.database).get(f.org, {
        targetId: f.onboard.targetId,
        ...f.onboard.credentials
      }).actorsReady
    ).toBe(false);
    expect(spy).not.toHaveBeenCalled();
    await expect(f.mapping.preview(f.org, f.onboard.input)).rejects.toThrow("CREDENTIAL_BINDING_INVALID");
    replace("2099-01-01T00:00:00Z");
    f.vault.setEnabled(id, false);
    await expect(f.mapping.preview(f.org, f.onboard.input)).rejects.toThrow("CREDENTIAL_BINDING_INVALID");
    f.vault.setEnabled(id, true);
    await expect(f.mapping.preview(randomUUID(), f.onboard.input)).rejects.toThrow("OWNED_LOOPBACK_TARGET_REQUIRED");
    const original = new TargetRepository(f.database).get(f.onboard.targetId)!;
    const targetId = new TargetRepository(f.database).create({
      organizationId: f.org,
      displayName: "Other generated target",
      tags: [],
      baseOrigin: f.origin,
      classification: "LOCAL",
      authorizationType: "OWNED",
      authorizationSummary: "Separately owned local fixture",
      approvedScope: original.approvedScope
    });
    await expect(f.mapping.preview(f.org, { ...f.onboard.input, targetId })).rejects.toThrow(
      "CREDENTIAL_BINDING_INVALID"
    );
    expect(f.wire).toEqual([]);
    f.capture("CREDENTIAL_SCOPE_REFUSALS", { readinessDecryption: false, requests: 0 });
    spy.mockRestore();
  } finally {
    await f.close();
  }
});
it("rejects repeated real principals even when roles and credential references differ", async () => {
  const f = await tenantlessApplicationFixture();
  try {
    const c = f.vault.getSummary(f.onboard.credentials.primary, f.org)!,
      id = f.vault.create({
        organizationId: f.org,
        targetId: f.onboard.targetId,
        name: "Duplicate generated principal",
        safeAlias: "Duplicate",
        safeIdentitySummary: { ...c.safeIdentitySummary, role: "different-role" },
        expiresAt: "2099-01-01T00:00:00Z",
        secret: f.vault.decryptForHealthCheck(c.id)
      });
    await expect(
      f.mapping.preview(f.org, { ...f.onboard.input, credentials: { ...f.onboard.credentials, account_b: id } })
    ).rejects.toThrow("DISTINCT_ACTOR_CONTEXTS_REQUIRED");
    expect(f.wire).toEqual([]);
  } finally {
    await f.close();
  }
});
it("mode switching after review preserves the immutable record and refuses dispatch", async () => {
  const f = await tenantlessApplicationFixture();
  try {
    const r = await f.mapping.create(f.org, f.onboard.input, "operator"),
      before = f.database.db
        .prepare("SELECT input_json,request_json,digest FROM application_mapping_revisions WHERE id=?")
        .get(r.revisionId),
      id = f.onboard.credentials.primary,
      c = f.vault.getSummary(id, f.org)!;
    f.vault.updateMetadata(id, {
      organizationId: f.org,
      targetId: f.onboard.targetId,
      name: c.name,
      safeAlias: c.safeAlias,
      expiresAt: c.expiresAt,
      safeIdentitySummary: { ...c.safeIdentitySummary, identityModel: "TENANT_AWARE", tenantId: "generated-tenant" }
    });
    await expect(f.mapping.execute(f.org, r.revisionId, r.digest, "operator")).rejects.toThrow();
    expect(
      f.database.db
        .prepare("SELECT input_json,request_json,digest FROM application_mapping_revisions WHERE id=?")
        .get(r.revisionId)
    ).toEqual(before);
    expect(f.database.db.prepare("SELECT count(*) n FROM application_mapping_dispatches").get()).toEqual({ n: 0 });
    expect(f.wire).toEqual([]);
    f.capture("MODE_SWITCH_REFUSAL", { before, requests: 0 });
  } finally {
    await f.close();
  }
});
it("changed credentials invalidate native evidence and prevent tenant-isolation policy from a tenantless source", async () => {
  const f = await tenantlessApplicationFixture();
  try {
    const a = await f.acquire(),
      count = f.wire.length;
    const p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
    await expect(
      f.mapping.createMatrix(
        f.org,
        a.revision.revisionId,
        {
          policyConfirmed: true,
          expectations: [
            {
              routeId: "onboarded-seed",
              url: f.origin + "/object",
              kind: "TENANT_ISOLATION",
              explanation: "Never invent a tenant boundary for this generated principal role source",
              identity: { path: "id", expectedValue: "generated-shared-object" },
              tenant: { path: "id", expectedValue: "generated-shared-object" },
              decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
            }
          ]
        },
        "operator"
      )
    ).rejects.toThrow("TENANT_PROOF_FORBIDDEN");
    const id = f.onboard.credentials.primary;
    f.vault.replaceSecret(id, {
      ...f.vault.decryptForHealthCheck(id),
      authorizationHeader: "Bearer generated-renewed-primary"
    });
    expect(() => f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator")).toThrow(
      "AUTHORITY_CHANGED"
    );
    expect(f.wire.length).toBe(count);
    expect(f.hypotheses.get(f.org, p.proposalId).freshness).not.toBe("CURRENT");
    f.capture("CHANGED_CREDENTIAL_AND_TENANT_PROOF_REFUSAL", { proposal: p.proposalId, requestsAfterRebinding: 0 });
  } finally {
    await f.close();
  }
});
