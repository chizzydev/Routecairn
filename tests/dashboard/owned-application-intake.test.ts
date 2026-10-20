import { it, expect } from "vitest";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
import { ownedIntakeExport } from "../helpers/owned-intake-export.js";
import { OwnedApplicationIntakeService } from "../../src/dashboard/execution/OwnedApplicationIntake.js";
it("retains offline owner evidence without traffic, binds exact routes and authority, then uses the existing native identity mapper", async () => {
  const f = await deepBusinessFixture();
  try {
    const service = new OwnedApplicationIntakeService(f.database),
      artifact = ownedIntakeExport(f),
      input = {
        targetId: f.targetId,
        credentials: f.credentials,
        artifact,
        ownerScopeConfirmed: true,
        offlineOnlyConfirmed: true
      },
      r = service.create(f.org, input, "operator");
    expect(f.wire).toHaveLength(0);
    expect(r.identityStatus).toBe("DECLARED_NOT_NATIVE_VERIFIED");
    expect(JSON.stringify(r)).not.toContain("Bearer");
    expect(r.requestsSent).toBe(0);
    expect(() =>
      service.create(f.org, { ...input, artifact: { ...artifact, headers: { authorization: "secret" } } }, "operator")
    ).toThrow();
    expect(() =>
      service.create(f.org, { ...input, artifact: { ...artifact, origin: "https://external.example" } }, "operator")
    ).toThrow("ORIGIN");
    expect(() =>
      service.create(
        f.org,
        { ...input, artifact: { ...artifact, routes: [...artifact.routes, artifact.routes[0]] } },
        "operator"
      )
    ).toThrow("DUPLICATE");
    expect(() =>
      service.create(
        f.org,
        {
          ...input,
          artifact: {
            ...artifact,
            actors: artifact.actors.map((a) => ({ ...a, principalFingerprint: "0".repeat(16) }))
          }
        },
        "operator"
      )
    ).toThrow("ACTOR");
    expect(() =>
      f.database.db.prepare("UPDATE application_owned_intakes SET digest='x' WHERE id=?").run(r.revisionId)
    ).toThrow("IMMUTABLE");
    await expect(f.mapping.preview(f.org, { ...r.draft, routes: r.draft.routes.slice(0, 2) })).rejects.toThrow(
      "BINDINGS_CHANGED"
    );
    const a = await f.acquire(r.draft);
    expect(a.result.status).toBe("COMPLETED");
    expect(a.result.input.intakeBinding?.digest).toBe(r.digest);
    expect(f.wire.every((r) => r.method === "GET")).toBe(true);
    f.capture("OFFLINE_INTAKE_TO_NATIVE_OBSERVATION", { receipt: r, result: a.result });
    f.database.db.prepare("UPDATE credential_profiles SET enabled=0 WHERE id=?").run(f.credentials.account_a);
    await expect(f.mapping.preview(f.org, r.draft)).rejects.toThrow("CREDENTIAL");
  } finally {
    await f.close();
  }
});
