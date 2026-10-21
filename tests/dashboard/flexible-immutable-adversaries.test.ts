import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { randomUUID } from "node:crypto";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { actorRegistryDigest } from "../../src/core/auth/ActorRegistry.js";
it.each(["actor-order", "credential-replacement", "organization"] as const)(
  "native dashboard refuses %s changes after reviewed preview before worker activation",
  async (mode) => {
    const f = await flexibleDashboardFixture(2);
    try {
      const preview = await f.execution.preview(f.request),
        request = structuredClone(f.request);
      request.studio = { ...request.studio!, previewIdentity: preview.previewIdentity };
      if (mode === "actor-order") {
        request.actorRegistry!.actors.reverse();
        request.targetAuthorization!.productionCampaign = {
          ...request.targetAuthorization!.productionCampaign!,
          actorRegistryDigest: actorRegistryDigest(request.actorRegistry!),
          actorIds: request.actorRegistry!.actors.map((a) => a.id)
        } as NonNullable<typeof request.targetAuthorization>["productionCampaign"];
      } else if (mode === "credential-replacement")
        f.vault.replaceSecret(f.actors[0]!.credentialProfileId, {
          headers: { Authorization: "Bearer fixture-replaced-" + randomUUID() }
        });
      else request.actorRegistry!.organizationId = "foreign-organization";
      await expect(f.execution.enqueue(request, undefined, undefined, f.org)).rejects.toThrow();
      expect(f.wire).toEqual([]);
      expect(f.database.db.prepare("SELECT count(*) n FROM scan_workers").get()).toEqual({ n: 0 });
      f.capture("IMMUTABLE_REGISTRY_REPLAY_REFUSED", {
        mode,
        wire: f.wire,
        integrity: f.database.db.pragma("integrity_check"),
        foreignKeys: f.database.db.pragma("foreign_key_check"),
        workerCount: 0
      });
    } finally {
      await f.close();
    }
  }
);
