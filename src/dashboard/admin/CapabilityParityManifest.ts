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
  "advanced.production-mutation",
  "advanced.live-target-acceptance"
] as const;

export const dashboardRequiredOperationalCapabilities = [
  "workers.resource-governance-and-operations",
  "browser.connection-boundary",
  "credentials.lifecycle",
  "adaptive-security.intelligence-and-drift",
  "fixture-provider-adapters.versioned-execution"
  ,"continuous-assurance.scheduling-and-evidence"
  ,"operations.organizations-sso-and-rbac"
  ,"operations.remote-agents-and-sync"
  ,"operations.distributed-mutation-coordination"
  ,"operations.notifications-backup-and-integrations"
  ,"operations.sandboxed-module-sdk"
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
  { id: "transport.origin-isolated-pooling", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD", "INTERNAL"], dashboardOperation: "GUIDED_BUILDER", safety: "Per-origin and per-selected-IP pools, dispatch-time DNS policy validation, remote-address verification, bounded lifetime and capacity, TLS-only HTTP/2 without cross-origin coalescing, and redacted performance diagnostics." },
  { id: "adaptive-security.intelligence-and-drift", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Completed evidence is reduced to safe canonical models. Anonymous observations and exact completed engine contracts can become immutable Scan Studio cases, including authenticated/object-bound reads, signed exports, operational flows, synthetic billing, and business-state changes. Writes require a conclusive prior contract, verified cleanup, current credential fixtures, explicit approval, reserved cleanup capacity, and an unmodified execution fingerprint." },
  { id: "fixture-provider-adapters.versioned-execution", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Provider fixtures are target-bound, encrypted, immutable after review, credential-version-aware, recommendation-linked, revalidated at preview and launch, and cannot enable real payment execution." },
  { id: "continuous-assurance.scheduling-and-evidence", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Scheduled and deployment-triggered runs execute only immutable reviewed adapter versions under unexpired authorization, global cleanup gates, installation leases, exact-case regression gates, quiet-success notifications, and encrypted evidence retention." },
  { id: "operations.organizations-sso-and-rbac", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Organization-scoped projects, targets, scans, findings, credentials and histories; automatic legacy assignment; server-enforced resource boundaries; membership roles; final-owner protection; and verified OIDC login." },
  { id: "operations.remote-agents-and-sync", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Deployable TLS control plane, native signed workers, organization-scoped live-resource merge with deterministic conflict ordering and soft-deletion state, destination-key credential re-encryption, cross-installation organization mapping, signed batches, monotonic cursors, and optional safe-event-only federation." },
  { id: "operations.distributed-mutation-coordination", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "HMAC-authenticated replay-resistant cross-host leases, persistent namespace uniqueness, local-plus-remote cleanup gates, non-reassigning stale leases, recovery-only obligation entry, and audited operator orphan/resolve controls." },
  { id: "operations.notifications-backup-and-integrations", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Durable idempotent notification outbox, bounded retries, pinned outbound transport, environment-backed secrets, consistent encrypted backups with verified restart-only restore, PDF proof packs, and SARIF/JUnit/Burp/JSON exports." },
  { id: "operations.sandboxed-module-sdk", status: "FULL", surfaces: ["API", "DASHBOARD", "INTERNAL"], dashboardOperation: "MANAGED_WORKSPACE", safety: "Immutable package digests, separate approval, Node permission sandbox, no network or child-process authority, package-only read access, and bounded memory, runtime, input, output, and schemas." },
  ...dashboardRequiredAdvancedCapabilities.map((id) => ({ id, status: "FULL" as const, surfaces: ["API", "DASHBOARD"] as const, dashboardOperation: id === "advanced.production-mutation" || id === "advanced.live-target-acceptance" ? "MANAGED_WORKSPACE" as const : "GUIDED_BUILDER" as const })),
  { id: "controlled-mutation.execution-and-recovery", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD"], safety: "Dashboard approval and recovery require disposable targets, exact contracts, encrypted checkpoints, fresh credentials, and independent rollback verification." },
  { id: "workflow-mutation.cleanup-recovery", status: "FULL", surfaces: ["CLI", "API", "DASHBOARD", "INTERNAL"], safety: "Local and cross-host coordination plus encrypted crash recovery across dedicated engines. Explicit cleanup-only approval never authorizes replaying original attack steps." },
  { id: "controlled-mutation.cleanup-visibility", status: "FULL", surfaces: ["API", "DASHBOARD"], safety: "Read-only, redacted mutation stages and cleanup obligations; recovery payloads remain encrypted and are never returned." },
  { id: "first-owner.bootstrap", status: "FULL", surfaces: ["CLI", "INTERNAL"], owner: "deployment operator", safety: "Supports an interactive local CLI and one-time environment/file-backed deployment bootstrap; both enforce the password policy and stop applying bootstrap material once an enabled owner exists." },
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
