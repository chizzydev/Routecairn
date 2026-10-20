import { it, expect } from "vitest";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
import { hypothesisSource } from "../../src/dashboard/execution/ApplicationHypothesisBinding.js";
import { readActorObservation } from "../../src/dashboard/execution/ObservedActorEvidence.js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
it("requires exact primary/A/B native attribution, credential, identity and route provenance", async () => {
  const f = await transitionApplicationFixture("procurement");
  try {
    f.setFixed();
    const native = await f.acquire(),
      source = hypothesisSource(f.database, f.org, native.revision.revisionId),
      matrix: unknown[] = [];
    for (const actor of ["primary", "account-a", "account-b"]) {
      const valid = readActorObservation(source, "source", actor);
      expect(valid.bindingValid).toBe(true);
      for (const fault of [
        "wrong-slot",
        "wrong-actor",
        "wrong-credential",
        "wrong-role-proof",
        "wrong-tenant-proof",
        "wrong-route",
        "wrong-url",
        "wrong-plan",
        "wrong-decision",
        "duplicate-check",
        "duplicate-plan",
        "duplicate-marker",
        "bad-fingerprint",
        "blocked"
      ]) {
        const clone = structuredClone(source),
          o = readActorObservation(clone, "source", actor),
          check = o.check!,
          plan = clone.report!.scanPlan.apiGraphql!,
          proof =
            actor === "primary"
              ? clone.report!.identityVerification!.primary
              : actor === "account-a"
                ? clone.report!.identityVerification!.accountA
                : clone.report!.identityVerification!.accountB;
        if (fault === "wrong-slot") check.authSlot = "anonymous";
        if (fault === "wrong-actor") check.actorId = "anonymous";
        if (fault === "wrong-credential") clone.row.request_json = "{}";
        if (fault === "wrong-role-proof") proof!.roleHash = "0".repeat(16);
        if (fault === "wrong-tenant-proof") proof!.tenantHash = "0".repeat(16);
        if (fault === "wrong-route") check.routeIds = ["operation"];
        if (fault === "wrong-url") plan.routes[0]!.urlFingerprint = "0".repeat(64);
        if (fault === "wrong-plan") plan.checks.find((c) => c.id === check.checkId)!.actorId = "anonymous";
        if (fault === "wrong-decision")
          check.requests[0]!.decision = "UNCLASSIFIED" as (typeof check.requests)[0]["decision"];
        if (fault === "duplicate-check")
          clone.report!.apiGraphql!.checks = [...clone.report!.apiGraphql!.checks, structuredClone(check)];
        if (fault === "duplicate-plan")
          Object.assign(plan, {
            checks: [...plan.checks, structuredClone(plan.checks.find((c) => c.id === check.checkId)!)]
          });
        if (fault === "duplicate-marker") {
          if (check.observedMarkers!.length)
            check.observedMarkers = [...check.observedMarkers!, structuredClone(check.observedMarkers![0]!)];
          else
            check.observedMarkers = [
              { path: "record.number", scalarType: "number", valueFingerprint: "0".repeat(64) },
              { path: "record.number", scalarType: "number", valueFingerprint: "0".repeat(64) }
            ];
        }
        if (fault === "bad-fingerprint") check.comparisonFingerprint = "0".repeat(64);
        if (fault === "blocked") check.outcome = "BLOCKED";
        const result = readActorObservation(clone, "source", actor);
        matrix.push({ actor, fault, valid: result.bindingValid, reasons: result.missingControls });
        expect(result.bindingValid, actor + ":" + fault).toBe(false);
      }
    }
    writeFileSync(join(f.root, "NATIVE_ACTOR_ADVERSARIAL_EQUIVALENCE.json"), JSON.stringify(matrix, null, 2), {
      flag: "wx"
    });
  } finally {
    await f.close();
  }
});
