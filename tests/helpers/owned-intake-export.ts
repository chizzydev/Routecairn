import { createHash } from "node:crypto";
import type { deepBusinessFixture } from "./deep-businessflow-fixture.js";
import { identityFingerprint } from "../../src/dashboard/execution/ObservedActorEvidence.js";
export function ownedIntakeExport(f: Awaited<ReturnType<typeof deepBusinessFixture>>) {
  const sha = (v: string) => createHash("sha256").update(v).digest("hex");
  return {
    version: 1 as const,
    kind: "OWNER_EVIDENCE_EXPORT" as const,
    origin: f.origin,
    capturedAt: new Date().toISOString(),
    exportSha256: sha(JSON.stringify(f.input.routes)),
    provenance: "SELF_MAINTAINED_FIXTURE" as const,
    actors: Object.entries(f.truth.actors).map(([slot, a]) => ({
      slot: slot as "primary" | "account_a" | "account_b",
      principalFingerprint: identityFingerprint(a.principal),
      tenantFingerprint: identityFingerprint(a.tenant),
      roleFingerprint: identityFingerprint(a.role),
      sessionEvidenceSha256: sha("Owned disposable fixture session contract " + slot)
    })),
    routes: f.input.routes
  };
}
