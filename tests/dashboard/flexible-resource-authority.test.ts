import { expect, it as platformTest } from "vitest";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { prepareAssessmentActors } from "../../src/dashboard/execution/AssessmentActorRegistry.js";
const it = platformTest.skipIf(process.platform !== "win32");
const policy = {
  id: "owned",
  kind: "OBJECT_OWNERSHIP",
  path: "/object/actor0",
  pathTemplate: "/object/:id",
  policyReference: "Explicit reviewed owned synthetic resource",
  reviewed: true,
  ownerActorId: "actor0",
  ownerPath: "owner",
  ownerValue: "actor0"
};
it.each(["owner", "review", "path", "actor", "duplicate", "bytes", "prerequisite"])(
  "rejects invalid resource %s without target traffic",
  async (mode) => {
    const f = await flexibleDashboardFixture(2);
    try {
      let resources: unknown[] = [{ ...policy }];
      if (mode === "owner") resources = [{ ...policy, ownerValue: "foreign-owner" }];
      if (mode === "review") resources = [{ ...policy, reviewed: false }];
      if (mode === "path") resources = [{ ...policy, path: "//foreign.invalid/resource" }];
      if (mode === "actor") resources = [{ ...policy, ownerActorId: "foreign" }];
      if (mode === "duplicate") resources = [{ ...policy }, { ...policy }];
      if (mode === "bytes")
        resources = [
          {
            id: "owned",
            path: "/private",
            policyReference: policy.policyReference,
            reviewed: true,
            kind: "COLLECTION_OWNERSHIP",
            collection: {
              kind: "COLLECTION",
              algorithm: "bounded-native-collection-v1",
              collectionPath: "items",
              itemIdentityPath: "id",
              ownerPath: "owner",
              ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
              maxItems: 16,
              maxResponseBytes: 65536,
              coverage: "THIS_RESPONSE_ONLY",
              pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
            }
          }
        ];
      if (mode === "prerequisite")
        resources = [
          {
            id: "later",
            kind: "BUSINESS_READ",
            path: "/private",
            policyReference: policy.policyReference,
            reviewed: true,
            actorIds: ["actor0"],
            prerequisiteResourceId: "missing",
            markerPath: "state",
            markerValue: "ready"
          }
        ];
      expect(() => prepareAssessmentActors(f.database, f.vault, f.org, { ...f.input, resources })).toThrow();
      if (mode === "bytes")
        expect(() => prepareAssessmentActors(f.database, f.vault, f.org, { ...f.input, resources })).toThrow(
          "RESOURCE_POLICY_RESPONSE_BUDGET_EXCEEDED"
        );
      expect(f.wire).toEqual([]);
      f.capture("R3_INVALID_POLICY", { mode, wire: f.wire, integrity: f.database.db.pragma("integrity_check") });
    } finally {
      await f.close();
    }
  }
);
it.each(["resource-plan", "owner-policy", "expired-approval", "credential", "scope"])(
  "old native preview cannot authorize changed %s",
  async (mode) => {
    const f = await flexibleDashboardFixture(2);
    try {
      const p = prepareAssessmentActors(f.database, f.vault, f.org, { ...f.input, resources: [policy] });
      Object.assign(f.request, {
        actorRegistry: p.registry,
        actorCredentials: p.actorCredentials,
        apiGraphql: p.apiGraphql,
        targetAuthorization: p.targetAuthorization
      });
      const preview = await f.execution.preview(f.request),
        q = structuredClone(f.request);
      q.studio = { ...q.studio!, previewIdentity: preview.previewIdentity };
      if (mode === "resource-plan")
        q.apiGraphql!.routes.find((r) => r.id === "resource-owned")!.url = f.origin + "/private";
      if (mode === "owner-policy")
        q.actorRegistry!.workflows.find((w) => w.id === "resource-owned")!.ownerPolicySha256 = "e".repeat(64);
      if (mode === "expired-approval") {
        q.targetAuthorization!.productionCampaign!.startsAt = new Date(Date.now() - 3600000).toISOString();
        q.targetAuthorization!.productionCampaign!.expiresAt = new Date(Date.now() - 1000).toISOString();
      }
      if (mode === "credential")
        f.vault.replaceSecret(f.actors[0]!.credentialProfileId, {
          headers: { Authorization: "Bearer generated-replacement-only" }
        });
      if (mode === "scope") q.studio!.scope.disallowedPaths.push("/object");
      await expect(f.execution.enqueue(q, undefined, undefined, f.org)).rejects.toThrow();
      expect(f.wire).toEqual([]);
      expect(f.database.db.prepare("SELECT count(*) n FROM scan_workers").get()).toEqual({ n: 0 });
      f.capture("R3_STALE_RESOURCE_AUTHORITY", {
        mode,
        wire: f.wire,
        integrity: f.database.db.pragma("integrity_check"),
        workers: f.database.db.prepare("SELECT id,state FROM scan_workers").all()
      });
    } finally {
      await f.close();
    }
  }
);
