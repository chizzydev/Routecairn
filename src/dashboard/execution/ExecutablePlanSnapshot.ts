import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { routeCairnConfigSchema, scopeSchema, type RouteCairnConfig, type RouteCairnScope } from "../../config/ConfigSchema.js";
import type { ResolvedScanPlan } from "../../core/planning/ScanPlan.js";
import type { DashboardResolvedAuth, ResolvedPlanInputs } from "./ScanExecutionShared.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";

export const executablePlanSchemaVersion = 1 as const;
export const maxExecutablePlanBytes = 2 * 1024 * 1024;

export interface ExecutablePlanPayload {
  schemaVersion: typeof executablePlanSchemaVersion;
  target: string;
  targetOrigin: string;
  plan: ResolvedScanPlan;
  config: RouteCairnConfig;
  scope: RouteCairnScope;
  authenticationDigest: string;
  sourceBindings: readonly ExecutablePlanSourceBinding[];
}

export interface ExecutablePlanSourceBinding {
  kind: string;
  path: string;
  bytes: number;
  digest: string;
}

export interface BoundExecutablePlan {
  payload: ExecutablePlanPayload;
  contentDigest: string;
  binding: string;
}

export function createExecutablePlanPayload(target: string, resolved: ResolvedPlanInputs, auth: DashboardResolvedAuth, sourceBindings: readonly ExecutablePlanSourceBinding[] = []): ExecutablePlanPayload {
  const parsed = new URL(target);
  const payload: ExecutablePlanPayload = {
    schemaVersion: executablePlanSchemaVersion,
    target: parsed.href,
    targetOrigin: parsed.origin,
    plan: resolved.plan,
    config: resolved.config,
    scope: resolved.scope,
    authenticationDigest: executableAuthenticationDigest(auth),
    sourceBindings
  };
  return parseExecutablePlanPayload(JSON.parse(canonicalExecutablePlanJson(payload)));
}

export function parseExecutablePlanPayload(value: unknown): ExecutablePlanPayload {
  if (!isRecord(value) || value.schemaVersion !== executablePlanSchemaVersion) throw new Error("EXECUTABLE_PLAN_SCHEMA_INVALID");
  if (typeof value.target !== "string" || typeof value.targetOrigin !== "string") throw new Error("EXECUTABLE_PLAN_TARGET_INVALID");
  const target = new URL(value.target);
  if (target.origin !== value.targetOrigin) throw new Error("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");
  if (!isRecord(value.plan) || value.plan.schemaVersion !== 1 || !Array.isArray(value.plan.modules) || !isRecord(value.plan.metadata)) throw new Error("EXECUTABLE_PLAN_STRUCTURE_INVALID");
  if (typeof value.authenticationDigest !== "string" || !/^[a-f0-9]{64}$/.test(value.authenticationDigest)) throw new Error("EXECUTABLE_PLAN_AUTH_BINDING_INVALID");
  if (!Array.isArray(value.sourceBindings)) throw new Error("EXECUTABLE_PLAN_SOURCE_BINDING_INVALID");
  const sourceBindings = value.sourceBindings.map((entry) => {
    if (!isRecord(entry) || typeof entry.kind !== "string" || typeof entry.path !== "string" || typeof entry.bytes !== "number" || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || typeof entry.digest !== "string" || !/^[a-f0-9]{64}$/.test(entry.digest)) throw new Error("EXECUTABLE_PLAN_SOURCE_BINDING_INVALID");
    return { kind: entry.kind, path: entry.path, bytes: entry.bytes, digest: entry.digest };
  });
  const config = routeCairnConfigSchema.parse(value.config);
  const scope = scopeSchema.parse(value.scope);
  return deepFreeze({
    schemaVersion: executablePlanSchemaVersion,
    target: target.href,
    targetOrigin: target.origin,
    plan: value.plan as unknown as ResolvedScanPlan,
    config,
    scope,
    authenticationDigest: value.authenticationDigest,
    sourceBindings
  });
}

export async function captureExecutablePlanSources(request: DashboardScanCreateRequest): Promise<readonly ExecutablePlanSourceBinding[]> {
  const entries = manifestPathEntries(request);
  const bindings: ExecutablePlanSourceBinding[] = [];
  let totalBytes = 0;
  for (const [kind, rawPath] of entries) {
    const path = resolve(rawPath);
    const content = await readFile(path);
    totalBytes += content.length;
    if (totalBytes > maxExecutablePlanBytes) throw new Error("EXECUTABLE_PLAN_SOURCES_TOO_LARGE");
    bindings.push({ kind, path, bytes: content.length, digest: createHash("sha256").update(content).digest("hex") });
  }
  return deepFreeze(bindings);
}

export async function assertExecutablePlanSourcesUnchanged(bindings: readonly ExecutablePlanSourceBinding[]): Promise<void> {
  for (const binding of bindings) {
    try {
      const content = await readFile(binding.path);
      const digest = createHash("sha256").update(content).digest("hex");
      if (content.length !== binding.bytes || digest !== binding.digest) throw new Error("changed");
    } catch {
      throw new Error(`EXECUTABLE_PLAN_SOURCE_CHANGED:${binding.kind}`);
    }
  }
}

export function executablePlanContentDigest(payload: ExecutablePlanPayload): string {
  return createHash("sha256").update(`routecairn-executable-plan-v${executablePlanSchemaVersion}\n`).update(canonicalExecutablePlanJson(payload)).digest("hex");
}

export function executableAuthenticationDigest(auth: DashboardResolvedAuth | undefined): string {
  return createHash("sha256")
    .update("routecairn-executable-authentication-v1\n")
    .update(canonicalExecutablePlanJson({ authProfile: auth?.authProfile ?? null, authProfileSet: auth?.authProfileSet ?? null }))
    .digest("hex");
}

export function canonicalExecutablePlanJson(value: unknown): string {
  const normalized = normalize(value, new Set<object>());
  const serialized = JSON.stringify(normalized);
  if (Buffer.byteLength(serialized, "utf8") > maxExecutablePlanBytes) throw new Error("EXECUTABLE_PLAN_TOO_LARGE");
  return serialized;
}

function normalize(value: unknown, ancestors: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("EXECUTABLE_PLAN_VALUE_INVALID");
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    guardCycle(value, ancestors);
    const result = value.map((entry) => {
      if (entry === undefined) throw new Error("EXECUTABLE_PLAN_VALUE_INVALID");
      return normalize(entry, ancestors);
    });
    ancestors.delete(value);
    return result;
  }
  if (isRecord(value)) {
    guardCycle(value, ancestors);
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry !== undefined) result[key] = normalize(entry, ancestors);
    }
    ancestors.delete(value);
    return result;
  }
  throw new Error("EXECUTABLE_PLAN_VALUE_INVALID");
}

function guardCycle(value: object, ancestors: Set<object>): void {
  if (ancestors.has(value)) throw new Error("EXECUTABLE_PLAN_VALUE_INVALID");
  ancestors.add(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function manifestPathEntries(request: DashboardScanCreateRequest): Array<[string, string]> {
  const fields = [
    "scopeFile", "configFile", "authFile", "authAFile", "authBFile",
    "supabaseAuthorizationFile",
    "authenticationLifecycleFile", "authenticationLifecycleAutoFile", "businessInvariantFile",
    "controlledRaceFile", "apiGraphqlFile", "linkPortalSecurityFile",
    "operationalEndpointSecurityFile", "billingEntitlementFile", "assistedReviewFile",
    "preHandoverFile", "targetAuthorizationFile"
  ] as const;
  return fields.flatMap((field) => request[field] ? [[field, request[field]!] as [string, string]] : []);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
