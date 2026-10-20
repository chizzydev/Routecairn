import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
it("refuses a partial native report even when an owned fault fixture updates its registry hash", async () => {
  const f = await schemaApplicationFixture();
  try {
    const { mappingInput } = f.makeInput(),
      a = await f.mapping.create(f.org, mappingInput, "operator"),
      b = await f.mapping.create(f.org, mappingInput, "operator"),
      run = await f.mapping.execute(f.org, a.revisionId, a.digest, "operator");
    await f.wait(run.scanId!);
    await f.execution.shutdown();
    const artifact = f.database.db
      .prepare(
        "SELECT f.id,f.canonical_path FROM artifacts f JOIN scans s ON s.json_report_artifact_id=f.id WHERE s.id=?"
      )
      .get(run.scanId!) as { id: string; canonical_path: string };
    const original = readFileSync(artifact.canonical_path);
    writeFileSync(join(f.root, "ORIGINAL_NATIVE_REPORT_BEFORE_PARTIAL_FAULT.json"), original, { flag: "wx" });
    const report = JSON.parse(original.toString());
    report.execution.partial = true;
    const changed = JSON.stringify(report);
    writeFileSync(artifact.canonical_path, changed);
    const hash = createHash("sha256").update(changed).digest("hex");
    f.database.db.prepare("UPDATE artifacts SET scoped_or_full_safe_hash=? WHERE id=?").run(hash, artifact.id);
    expect(() =>
      f.comparisons.create(f.org, { baselineRevisionId: a.revisionId, currentRevisionId: b.revisionId }, "operator")
    ).toThrow("RESULT_INCOMPLETE");
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM application_map_comparisons").get()).toEqual({ n: 0 });
    expect(f.wire).toHaveLength(20);
    writeFileSync(
      join(f.root, "PARTIAL_FAULT_RECEIPT.json"),
      JSON.stringify(
        {
          deliberateOwnedFixtureFault: true,
          originalSha256: createHash("sha256").update(original).digest("hex"),
          faultedSha256: hash,
          registryDeliberatelyChanged: true,
          quietComparisonCreated: false
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  } finally {
    await f.close();
  }
});
