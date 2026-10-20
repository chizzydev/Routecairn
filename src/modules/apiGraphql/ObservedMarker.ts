import { createHash } from "node:crypto";
/** Explicit non-secret scalar markers only; response values never enter retained evidence. */
export function observedMarkerFingerprint(value: string | number): string {
  return createHash("sha256").update("routecairn-observed-marker-v1\0").update(JSON.stringify(value)).digest("hex");
}
