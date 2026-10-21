import type { TransientValueObservation } from "../evidence/ValuePresenceAttestation.js";
/** Local redaction knowledge is never evidence that a credential was transmitted. */
export function privateScrubContext(
  observation: TransientValueObservation,
  privateValues: readonly string[]
): TransientValueObservation {
  return {
    ...observation,
    values: [
      ...observation.values,
      ...privateValues.map((rawValue) => ({
        location: "header" as const,
        name: "private-redaction-only",
        classification: "opaque-auth-value" as const,
        rawValue
      }))
    ]
  };
}

import type { RequestAuditEntry } from "./HttpTypes.js";
export function privateAuditRecorder(record: (entry: RequestAuditEntry) => void, names: readonly string[]) {
  const privateHeaders = new Set(names.map((name) => name.toLowerCase()));
  return (entry: RequestAuditEntry) =>
    record({
      ...entry,
      requestHeaders: Object.fromEntries(
        Object.entries(entry.requestHeaders).map(([name, value]) => [
          name,
          privateHeaders.has(name.toLowerCase()) ? "<redacted>" : value
        ])
      )
    });
}
