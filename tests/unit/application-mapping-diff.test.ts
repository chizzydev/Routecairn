import { it, expect } from "vitest";
import { diffApplicationMaps } from "../../src/dashboard/execution/ApplicationMapComparison.js";
type Snapshot = Parameters<typeof diffApplicationMaps>[0];
function map(status = "COMPLETED"): Snapshot {
  return {
    revisionId: "r",
    revisionDigest: "a".repeat(64),
    sourceHash: "b".repeat(64),
    schemaProvenance: null,
    status,
    routes: [
      {
        key: "route",
        routeId: "r",
        url: "http://127.0.0.1/record/42",
        template: "/record/:id",
        kind: "OBJECT",
        identityPath: "record.id",
        tenantPath: null,
        cells: [
          {
            actorId: "primary",
            classification: "ALLOWED",
            statusCode: 200,
            nativeOutcome: "PASS",
            markerTypes: [{ path: "record.id", type: "number" }]
          }
        ]
      }
    ]
  };
}
it("makes missing selected marker evidence UNKNOWN rather than unchanged or disappeared", () => {
  const a = map(),
    b = map();
  b.routes[0]!.cells[0]!.markerTypes = [{ path: "record.id", type: "UNOBSERVED" }];
  expect(diffApplicationMaps(a, b).routes[0]!.cells[0]!.markerTypes[0]!.change).toBe("UNKNOWN");
});
it("keeps missing native actor evidence UNKNOWN", () => {
  const a = map(),
    b = map();
  b.routes[0]!.cells = [];
  expect(diffApplicationMaps(a, b).routes[0]!.cells[0]!.accessChange).toBe("UNKNOWN");
});
it("never interprets an unfinished map as observed endpoint disappearance", () => {
  const a = map(),
    b = map("INTERRUPTED");
  b.routes = [];
  const diff = diffApplicationMaps(a, b);
  expect(diff.status).toBe("UNKNOWN");
  expect(diff.routes[0]).toMatchObject({
    membership: "REMOVED_DECLARED_SEED",
    observation: "UNKNOWN_INCOMPLETE_EVIDENCE"
  });
  expect(diff.authorizationPolicyInferred).toBe(false);
});
