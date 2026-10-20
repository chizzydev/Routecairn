import { createHash } from "node:crypto";
import { z } from "zod";
import { ownedApplicationIntakeSchema } from "../contracts/OwnedApplicationIntakeContracts.js";
/** Pure offline minimization; never imports network clients or emits HAR bodies/headers. */
export function minimizeOwnedHar(bytes: Buffer, metadata: unknown) {
  if (bytes.length > 8 * 1024 * 1024) throw Error("OWNED_HAR_SIZE_BOUND");
  const m = ownedApplicationIntakeSchema.shape.artifact
      .omit({ kind: true, exportSha256: true, capturedAt: true })
      .parse(metadata),
    raw = JSON.parse(bytes.toString("utf8"));
  const entries = z
    .array(
      z
        .object({
          startedDateTime: z.string().datetime(),
          request: z.object({ method: z.string(), url: z.string().url() }).passthrough()
        })
        .passthrough()
    )
    .max(2000)
    .parse(raw?.log?.entries);
  const selected = m.routes.map((r) => {
    const matches = entries.filter((e) => e.request.url === r.url && e.request.method === "GET");
    if (!matches.length) throw Error("OWNED_HAR_REVIEWED_GET_MISSING");
    return matches.at(-1)!;
  });
  const artifact = {
    ...m,
    kind: "MINIMIZED_HAR" as const,
    exportSha256: createHash("sha256").update(bytes).digest("hex"),
    capturedAt: selected
      .map((e) => e.startedDateTime)
      .sort()
      .at(-1)!
  };
  return ownedApplicationIntakeSchema.shape.artifact.parse(artifact);
}
