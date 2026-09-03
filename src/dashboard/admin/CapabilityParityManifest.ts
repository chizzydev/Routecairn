export type CapabilityParityStatus = "FULL" | "INTENTIONAL_CLI_ONLY" | "INTERNAL_ONLY";

export interface CapabilityParityEntry {
  id: string;
  status: CapabilityParityStatus;
  surfaces: readonly ("CLI" | "API" | "DASHBOARD" | "INTERNAL")[];
  reason?: string;
  owner?: string;
  safety?: string;
}

export const capabilityParityManifest: readonly CapabilityParityEntry[] = [
  { id: "projects.lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "targets.lifecycle-and-defaults", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "configurations.versioned-lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "configurations.browser-import-export", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "settings.mutable-defaults", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "users.server-administration", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "credentials.lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "scan-studio", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"] },
  { id: "controlled-mutation.execution-and-recovery", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD"], safety: "Dashboard approval and recovery require disposable targets, exact contracts, encrypted checkpoints, fresh credentials, and independent rollback verification." },
  { id: "workflow-mutation.cleanup-recovery", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], safety: "Shared coordination and encrypted crash recovery across dedicated engines. Explicit cleanup-only approval never authorizes replaying original attack steps." },
  { id: "controlled-mutation.cleanup-visibility", status: "FULL", surfaces: ["API", "DASHBOARD"], safety: "Read-only, redacted mutation stages and cleanup obligations; recovery payloads remain encrypted and are never returned." },
  { id: "first-owner.bootstrap", status: "INTENTIONAL_CLI_ONLY", surfaces: ["CLI"], reason: "No authenticated owner exists yet to authorize a browser action.", owner: "deployment operator", safety: "Requires local CLI access and enforces the password policy." },
  { id: "credential-master-key.rotation", status: "INTENTIONAL_CLI_ONLY", surfaces: ["CLI"], reason: "Key rotation must not expose old or new key material to the browser process.", owner: "deployment operator", safety: "Runs offline with explicit key material and an audited key version." },
  { id: "database-migrations", status: "INTERNAL_ONLY", surfaces: ["INTERNAL"], reason: "Applied automatically before the dashboard accepts requests.", owner: "RouteCairn runtime", safety: "Transactional ordered schema versions." }
] as const;

export function validateCapabilityParityManifest(entries: readonly CapabilityParityEntry[] = capabilityParityManifest): string[] {
  const errors: string[] = [];
  for (const entry of entries) {
    if (!entry.id || entry.surfaces.length === 0) errors.push("Every parity entry requires an id and at least one surface.");
    if (entry.status === "INTENTIONAL_CLI_ONLY" && (!entry.reason || !entry.owner || !entry.safety)) errors.push(`${entry.id} requires reason, owner, and safety metadata.`);
    if (entry.status === "FULL" && (!entry.surfaces.includes("API") || !entry.surfaces.includes("DASHBOARD")) && !entry.surfaces.includes("INTERNAL")) errors.push(`${entry.id} is marked FULL without an executable product surface.`);
  }
  return errors;
}
