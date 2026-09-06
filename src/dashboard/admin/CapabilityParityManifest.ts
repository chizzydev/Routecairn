import { advancedEngineCatalog } from "../contracts/AdvancedEngineSchemas.js";

export type CapabilityParityStatus = "FULL" | "INTENTIONAL_CLI_ONLY" | "INTERNAL_ONLY";

export interface CapabilityParityEntry {
  id: string;
  status: CapabilityParityStatus;
  surfaces: readonly ("CLI" | "API" | "DASHBOARD" | "INTERNAL")[];
  reason?: string;
  owner?: string;
  safety?: string;
  dashboardOperation?: "GUIDED_BUILDER" | "MANAGED_WORKSPACE" | undefined;
}

export const dashboardRequiredAdvancedCapabilities = [
  ...advancedEngineCatalog.map((engine) => `advanced.${engine.id}`),
  "advanced.production-mutation"
] as const;

export const dashboardRequiredOperationalCapabilities = [
  "workers.resource-governance-and-operations",
  "browser.connection-boundary",
  "credentials.lifecycle"
] as const;

export const capabilityParityManifest: readonly CapabilityParityEntry[] = [
  { id: "projects.lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "targets.lifecycle-and-defaults", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "configurations.versioned-lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "configurations.browser-import-export", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "settings.mutable-defaults", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "users.server-administration", status: "FULL", surfaces: ["API", "DASHBOARD"] },
  { id: "credentials.lifecycle", status: "FULL", surfaces: ["API", "DASHBOARD"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Encrypted renewal, explicit expiry and health states, bounded identity verification, dependency-impact bindings, safe health history, Account A/B drift warnings, and queue/start-time readiness enforcement." },
  { id: "scan-studio", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"] },
  { id: "workers.resource-governance-and-operations", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Immutable per-worker ceilings, cleanup-first termination, process-tree containment, durable diagnostics, crash-loop quarantine, and audited owner controls." },
  { id: "browser.connection-boundary", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Per-crawl authenticated loopback proxy, connection-time all-answer DNS validation, IP-literal socket pinning, redirect/origin enforcement, safe diagnostics, and one bounded fresh-generation restart." },
  ...dashboardRequiredAdvancedCapabilities.map((id) => ({ id, status: "FULL" as const, surfaces: ["API", "DASHBOARD"] as const, dashboardOperation: id === "advanced.production-mutation" ? "MANAGED_WORKSPACE" as const : "GUIDED_BUILDER" as const })),
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
    if (dashboardRequiredAdvancedCapabilities.includes(entry.id as typeof dashboardRequiredAdvancedCapabilities[number]) && (entry.status !== "FULL" || !entry.surfaces.includes("API") || !entry.surfaces.includes("DASHBOARD") || !entry.dashboardOperation)) errors.push(`${entry.id} cannot be complete without a dashboard-native operation contract.`);
    if (dashboardRequiredOperationalCapabilities.includes(entry.id as typeof dashboardRequiredOperationalCapabilities[number]) && (entry.status !== "FULL" || !entry.surfaces.includes("API") || !entry.surfaces.includes("DASHBOARD") || entry.dashboardOperation !== "MANAGED_WORKSPACE")) errors.push(`${entry.id} cannot be complete without a managed dashboard diagnostics and control surface.`);
  }
  for (const id of dashboardRequiredAdvancedCapabilities) if (!entries.some((entry) => entry.id === id)) errors.push(`${id} is missing from capability parity.`);
  for (const id of dashboardRequiredOperationalCapabilities) if (!entries.some((entry) => entry.id === id)) errors.push(`${id} is missing from capability parity.`);
  return errors;
}
