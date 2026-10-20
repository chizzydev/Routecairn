import { it, expect } from "vitest";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
it("refuses duplicate real actor identities even when their saved credential references differ", async () => {
  const f = await applicationMappingFixture();
  try {
    const c = f.vault.getSummary(f.mappingInput.credentials.primary, f.org)!;
    const duplicate = f.vault.create({
      organizationId: f.org,
      targetId: f.input.targetId,
      name: "Generated duplicated actor reference",
      safeAlias: "Duplicate identity",
      safeIdentitySummary: c.safeIdentitySummary,
      expiresAt: "2099-01-01T00:00:00.000Z",
      secret: f.vault.decryptForHealthCheck(c.id)
    });
    let accepted = false,
      reason: string | undefined;
    try {
      await f.mapping.preview(f.org, {
        ...f.mappingInput,
        credentials: { ...f.mappingInput.credentials, account_a: duplicate }
      });
      accepted = true;
    } catch (e) {
      reason = e instanceof Error ? e.message : String(e);
    }
    writeFileSync(
      join(f.root, "DUPLICATE_ACTOR_IDENTITY_RECEIPT.json"),
      JSON.stringify(
        { accepted, reason, distinctCredentialReferences: true, samePrincipalAndTenant: true, wire: f.wire },
        null,
        2
      ),
      { flag: "wx" }
    );
    expect(f.wire).toHaveLength(0);
    expect(accepted).toBe(false);
  } finally {
    await f.close();
  }
});
it("refuses changed native mapping evidence and retains its original bytes without sending another request", async () => {
  const f = await applicationMappingFixture();
  try {
    const a = await f.acquire(),
      count = f.wire.length,
      artifact = f.database.db
        .prepare("SELECT a.canonical_path FROM scans s JOIN artifacts a ON a.id=s.json_report_artifact_id WHERE s.id=?")
        .get(a.run.scanId) as { canonical_path: string };
    const bytes = readFileSync(artifact.canonical_path);
    writeFileSync(join(f.root, "MAPPING_SOURCE_BEFORE_TAMPER.json"), bytes, { flag: "wx" });
    writeFileSync(artifact.canonical_path, Buffer.concat([bytes, Buffer.from(" ")]));
    expect(() => f.mapping.result(f.org, a.revision.revisionId)).toThrow("SOURCE_CHANGED");
    await expect(f.mapping.createMatrix(f.org, a.revision.revisionId, f.policy, "operator")).rejects.toThrow(
      "SOURCE_CHANGED"
    );
    expect(f.wire).toHaveLength(count);
    f.capture("MAPPING_SOURCE_TAMPER_REFUSAL");
  } finally {
    await f.close();
  }
});
