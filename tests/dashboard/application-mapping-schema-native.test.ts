import { it, expect } from "vitest";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
it("assesses the independent numeric application with real native acquisition, proof, remediation and retained findings comparison", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { schema, mappingInput } = f.makeInput();
    expect(f.wire).toEqual([]);
    expect(schema.excluded).toHaveLength(4);
    expect(schema.candidates).toHaveLength(4);
    const acquired = await f.mapping.create(f.org, mappingInput, "operator");
    expect(f.wire).toHaveLength(0);
    const a = await f.mapping.execute(f.org, acquired.revisionId, acquired.digest, "operator");
    await f.wait(a.scanId!);
    const map = f.mapping.result(f.org, acquired.revisionId);
    expect(map.observations[0]!.cells[0]!.observedMarkers).toContainEqual(
      expect.objectContaining({ path: "record.number", scalarType: "number" })
    );
    const policy = f.policyFor(mappingInput),
      before = await f.mapping.createMatrix(f.org, acquired.revisionId, policy, "operator");
    expect(before.blockers).toEqual([]);
    const b = await f.service.execute(f.org, before.revisionId, before.digest, "operator");
    await f.wait(b.scanId!);
    const vulnerable = f.service.result(f.org, before.revisionId);
    if (!("checks" in vulnerable)) throw Error("Evidence missing");
    expect(vulnerable.findings).toHaveLength(2);
    expect(vulnerable.checks.filter((c) => c.checkId.startsWith("schema-route-3") && c.outcome === "FAIL")).toEqual([]);
    f.setFixed();
    const after = await f.mapping.createMatrix(f.org, acquired.revisionId, policy, "operator"),
      c = await f.service.execute(f.org, after.revisionId, after.digest, "operator");
    await f.wait(c.scanId!);
    const fixed = f.service.result(f.org, after.revisionId);
    expect(fixed).toMatchObject({ findings: [], verifiedPass: false, status: "INCONCLUSIVE" });
    const compare = new ScanComparisonService(f.database).compare(b.scanId!, c.scanId!, {
      createdByUserId: "operator"
    });
    expect(compare.summary.resolved).toBe(2);
    expect(f.wire).toHaveLength(60);
    expect(f.wire.every((r) => r.method === "GET")).toBe(true);
    f.capture("NUMERIC_SCHEMA_ASSESSMENT");
  } finally {
    await f.close();
  }
});
it("retains immutable observed-map comparisons including marker types and honest unknowns", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { mappingInput } = f.makeInput(),
      before = await f.mapping.create(f.org, mappingInput, "operator");
    const a = await f.mapping.execute(f.org, before.revisionId, before.digest, "operator");
    await f.wait(a.scanId!);
    f.setFixed();
    f.setStringMarker();
    const changed = {
      ...mappingInput,
      routes: mappingInput.routes.slice(0, 3),
      schemaBinding: { ...mappingInput.schemaBinding!, selections: mappingInput.schemaBinding!.selections.slice(0, 3) }
    };
    const after = await f.mapping.create(f.org, changed, "operator"),
      b = await f.mapping.execute(f.org, after.revisionId, after.digest, "operator");
    await f.wait(b.scanId!);
    const compare = f.comparisons.create(
      f.org,
      { baselineRevisionId: before.revisionId, currentRevisionId: after.revisionId },
      "operator"
    );
    expect(compare.status).toBe("OBSERVED_DIFFERENCES");
    expect(compare.routes.some((r) => r.membership === "REMOVED_DECLARED_SEED")).toBe(true);
    expect(compare.routes.flatMap((r) => r.cells).some((c) => c.accessChange === "CHANGED_HYPOTHESIS")).toBe(true);
    expect(
      compare.routes
        .flatMap((r) => r.cells)
        .flatMap((c) => c.markerTypes)
        .some((m) => m.change === "TYPE_CHANGED")
    ).toBe(true);
    expect(
      f.comparisons
        .create(f.org, { baselineRevisionId: after.revisionId, currentRevisionId: before.revisionId }, "operator")
        .routes.some((r) => r.membership === "ADDED_DECLARED_SEED")
    ).toBe(true);
    expect(compare.verifiedApplicationPass).toBe(false);
    expect(f.comparisons.result(f.org, compare.comparisonId)).toEqual(compare);
    expect(() =>
      f.database.db
        .prepare("UPDATE application_map_comparisons SET digest='changed' WHERE id=?")
        .run(compare.comparisonId)
    ).toThrow("IMMUTABLE_MAP_COMPARISON");
    expect(() =>
      f.database.db
        .prepare("DELETE FROM application_schema_revisions WHERE id=?")
        .run(mappingInput.schemaBinding!.revisionId)
    ).toThrow("IMMUTABLE_SCHEMA_REVISION");
    const unobserved = await f.mapping.create(f.org, mappingInput, "operator"),
      unknown = f.comparisons.create(
        f.org,
        { baselineRevisionId: before.revisionId, currentRevisionId: unobserved.revisionId },
        "operator"
      );
    expect(unknown.status).toBe("UNKNOWN");
    expect(unknown.routes.flatMap((r) => r.cells).every((c) => c.accessChange === "UNKNOWN")).toBe(true);
    expect(f.wire.every((r) => r.method === "GET")).toBe(true);
    expect(f.wire).toHaveLength(36);
    f.capture("IMMUTABLE_NUMERIC_MAP_COMPARISONS");
  } finally {
    await f.close();
  }
});
