import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
it("refuses duplicate reviewed proof identities even when a disposable fault fixture rebinds the file hash", async () => {
  const f = await applicationMappingFixture();
  try {
    const a = await f.acquire();
    const matrix = await f.mapping.createMatrix(f.org, a.revision.revisionId, f.policy, "operator");
    const proof = await f.service.execute(f.org, matrix.revisionId, matrix.digest, "operator");
    await f.wait(proof.scanId!);
    await f.execution.shutdown();
    const artifact = f.database.db
      .prepare(
        "SELECT f.id,f.canonical_path FROM artifacts f JOIN scans s ON s.json_report_artifact_id=f.id WHERE s.id=?"
      )
      .get(proof.scanId!) as { id: string; canonical_path: string };
    const original = readFileSync(artifact.canonical_path);
    writeFileSync(join(f.root, "ORIGINAL_NATIVE_REPORT_BEFORE_IDENTITY_FAULT.json"), original, { flag: "wx" });
    const r = JSON.parse(original.toString());
    r.apiGraphql.checks[1].checkId = r.apiGraphql.checks[0].checkId;
    const bytes = JSON.stringify(r);
    writeFileSync(artifact.canonical_path, bytes);
    f.database.db
      .prepare("UPDATE artifacts SET scoped_or_full_safe_hash=? WHERE id=?")
      .run(createHash("sha256").update(bytes).digest("hex"), artifact.id);
    writeFileSync(
      join(f.root, "CHECK_ID_FAULT_RECEIPT.json"),
      JSON.stringify(
        {
          fault: "duplicate exact native check ID; unchanged total count; registry hash deliberately rebound",
          originalSha256: createHash("sha256").update(original).digest("hex"),
          integrity: f.database.db.pragma("integrity_check"),
          requests: f.wire.length
        },
        null,
        2
      ),
      { flag: "wx" }
    );
    expect(() => f.service.result(f.org, matrix.revisionId)).toThrow("RESULT_INCOMPLETE");
    expect(f.wire).toHaveLength(40);
  } finally {
    await f.close();
  }
});
