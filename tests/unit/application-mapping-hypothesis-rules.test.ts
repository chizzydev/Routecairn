import { it, expect } from "vitest";
import { buildApplicationHypotheses } from "../../src/dashboard/execution/ApplicationSecurityHypotheses.js";
import type { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
type Map = ReturnType<ApplicationMappingService["result"]>;
function fixture() {
  const base = {
    status: "COMPLETED",
    sourceHash: "a".repeat(64),
    input: {
      targetId: "target",
      credentials: { primary: "p", account_a: "a", account_b: "b" },
      routes: [
        {
          id: "record",
          url: "http://127.0.0.1/records/42",
          pathTemplate: "/records/:id",
          kind: "OBJECT",
          identityPath: "record.id",
          tenantPath: "record.tenant"
        }
      ]
    },
    observations: [
      {
        routeId: "record",
        cells: ["primary", "account-a", "account-b", "anonymous"].map((actorId, i) => ({
          actorId,
          identityVerified: i < 3,
          nativeOutcome: "PASS",
          nativeDecision: i === 3 ? "DENIED" : "ALLOWED",
          statusCode: i === 3 ? 401 : 200,
          tenantFingerprint: i === 2 ? "blue" : "red",
          observedMarkers:
            i === 3
              ? []
              : [
                  { path: "record.id", scalarType: "number", valueFingerprint: "1".repeat(64) },
                  { path: "record.tenant", scalarType: "string", valueFingerprint: "2".repeat(64) }
                ]
        }))
      }
    ]
  };
  return base as unknown as Map;
}
it("ranks observed shared markers without calling a legitimate or forbidden policy inferred", () => {
  const a = buildApplicationHypotheses(fixture(), "org", () => ["ir"]);
  expect(a[0]).toMatchObject({
    priority: 300,
    eligibility: "EVIDENCE_READY_FOR_POLICY_REVIEW",
    vulnerabilityConclusion: "NOT_ASSESSED",
    policyInferred: false,
    executionAuthority: "NONE"
  });
  expect(a[0]!.counterevidence.some((c) => c.reason === "NATIVE_DENIAL_OBSERVED")).toBe(true);
});
it.each([
  "missing-primary",
  "wrong-object",
  "typed-mismatch",
  "unsafe-empty-marker",
  "unknown-map",
  "unverified-actors",
  "fixed"
])("abstains on %s rather than generating a vulnerability", (fault) => {
  const m = fixture(),
    cells = m.observations[0]!.cells;
  if (fault === "missing-primary") cells[0]!.nativeOutcome = "BLOCKED";
  if (fault === "wrong-object")
    for (const c of cells.slice(1, 3)) c.observedMarkers[0]!.valueFingerprint = "3".repeat(64);
  if (fault === "typed-mismatch") for (const c of cells.slice(1, 3)) c.observedMarkers[0]!.scalarType = "string";
  if (fault === "unsafe-empty-marker") cells[0]!.observedMarkers = [];
  if (fault === "unknown-map") m.status = "UNKNOWN";
  if (fault === "unverified-actors") for (const c of cells.slice(1, 3)) c.identityVerified = false;
  if (fault === "fixed") for (const c of cells.slice(1, 3)) c.nativeDecision = "DENIED";
  expect(buildApplicationHypotheses(m, "org", () => ["ir"])[0]!.eligibility).toBe("ABSTAIN");
});
it("deduplicates exact logical routes, keeps stable IDs and uses deterministic tie ordering", () => {
  const m = fixture(),
    route = m.input.routes[0]!;
  m.input.routes.push({ ...route, id: "duplicate" });
  const one = buildApplicationHypotheses(m, "org", () => ["ir"]);
  expect(one).toHaveLength(1);
  const again = buildApplicationHypotheses(
    { ...m, input: { ...m.input, routes: [...m.input.routes].reverse() } },
    "org",
    () => ["ir"]
  );
  expect(again).toEqual(one);
});
