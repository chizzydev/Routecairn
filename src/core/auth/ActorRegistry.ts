import { z } from "zod";
import { createHash, createHmac } from "node:crypto";
import { open } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { authProfileSchema, parseAuthProfile, type AuthProfile } from "./AuthProfile.js";
import type { IdentityVerificationResult } from "../../reports/ReportTypes.js";
export const actorIdSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_-]{0,63}$/)
  .refine((v) => !["__proto__", "constructor", "prototype"].includes(v));
export const assessmentFamilySchema = z.enum([
  "PUBLIC_OBSERVATION",
  "AUTHENTICATED_OBSERVATION",
  "PRINCIPAL_OBSERVATION",
  "OWNERSHIP_COMPARISON",
  "ROLE_COMPARISON",
  "TENANT_COMPARISON",
  "BROWSER_OBSERVATION",
  "LEGACY_SPECIALIZED"
]);
export type AssessmentFamily = z.infer<typeof assessmentFamilySchema>;
export const workflowAuthorizationSchema = z
  .object({
    id: actorIdSchema,
    family: assessmentFamilySchema,
    actorIds: z.array(actorIdSchema).max(8),
    reviewed: z.literal(true),
    ownerPolicySha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    applicable: z.boolean().default(true)
  })
  .strict();
const exactOrigin = z
  .string()
  .url()
  .refine((v) => {
    const u = new URL(v);
    return ["http:", "https:"].includes(u.protocol) && u.origin === v;
  });
export const actorRegistrySchema = z
  .object({
    contractVersion: z.literal(2),
    bindingAlgorithm: z.literal("HMAC_SHA256_PROFILE_V1").default("HMAC_SHA256_PROFILE_V1"),
    registryId: z.string().uuid(),
    organizationId: z.string().min(1).max(120),
    targetOrigin: exactOrigin,
    actors: z
      .array(
        z
          .object({
            id: actorIdSchema,
            label: z.string().min(1).max(80),
            authentication: z.discriminatedUnion("mechanism", [
              z.object({ mechanism: z.literal("ANONYMOUS") }).strict(),
              z
                .object({
                  mechanism: z.enum(["BEARER", "COOKIE", "API_KEY", "BROWSER_SESSION"]),
                  credentialRef: z.string().min(1).max(160),
                  availability: z.enum(["AVAILABLE", "EXPIRED", "REVOKED", "MISSING"]).default("AVAILABLE"),
                  credentialDigest: z
                    .string()
                    .regex(/^[a-f0-9]{64}$/)
                    .optional(),
                  credentialExpiresAt: z.string().datetime(),
                  accountProvenance: z.enum(["FRESH_DISPOSABLE", "OWNER_APPROVED_EXISTING_TEST"]),
                  suitableForTesting: z.literal(true)
                })
                .strict()
            ]),
            principalFingerprint: z
              .string()
              .regex(/^[a-f0-9]{16}$/)
              .optional(),
            roleFingerprint: z
              .string()
              .regex(/^[a-f0-9]{16}$/)
              .optional(),
            tenantFingerprint: z
              .string()
              .regex(/^[a-f0-9]{16}$/)
              .optional()
          })
          .strict()
      )
      .max(8),
    workflows: z.array(workflowAuthorizationSchema).max(64)
  })
  .strict()
  .superRefine((v, c) => {
    const fail = (message: string) => c.addIssue({ code: z.ZodIssueCode.custom, message });
    if (new Set(v.actors.map((a) => a.id)).size !== v.actors.length) fail("DUPLICATE_ACTOR_ID");
    const authenticated = v.actors.filter((a) => a.authentication.mechanism !== "ANONYMOUS");
    if (
      new Set(
        authenticated.map((a) => (a.authentication.mechanism === "ANONYMOUS" ? "" : a.authentication.credentialRef))
      ).size !== authenticated.length
    )
      fail("DUPLICATE_CREDENTIAL_REFERENCE");
    for (const a of authenticated)
      if (
        a.authentication.mechanism !== "ANONYMOUS" &&
        a.authentication.availability === "AVAILABLE" &&
        !a.authentication.credentialDigest
      )
        fail("AVAILABLE_CREDENTIAL_BINDING_REQUIRED");
    if (new Set(v.workflows.map((w) => w.id)).size !== v.workflows.length) fail("DUPLICATE_WORKFLOW_ID");
    for (const a of v.actors)
      if (
        a.authentication.mechanism === "ANONYMOUS" &&
        (a.principalFingerprint || a.roleFingerprint || a.tenantFingerprint)
      )
        fail("ANONYMOUS_IDENTITY_DECLARATION");
    for (const w of v.workflows)
      if (new Set(w.actorIds).size !== w.actorIds.length || w.actorIds.some((id) => !v.actors.some((a) => a.id === id)))
        fail("UNKNOWN_OR_DUPLICATE_WORKFLOW_ACTOR");
    for (const w of v.workflows)
      for (const id of w.actorIds) {
        const actor = v.actors.find((a) => a.id === id);
        if (actor && (actor.authentication.mechanism === "ANONYMOUS") !== (w.family === "PUBLIC_OBSERVATION"))
          fail("ANONYMOUS_WORKFLOW_FAMILY_CONFLICT");
      }
  });
export type ActorRegistry = z.infer<typeof actorRegistrySchema>;
export const identityFingerprint = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
function canonical(v: unknown): unknown {
  return Array.isArray(v)
    ? v.map(canonical)
    : v && typeof v === "object"
      ? Object.fromEntries(
          Object.entries(v)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, x]) => [k, canonical(x)])
        )
      : v;
}
export function credentialDigest(v: AuthProfile, bindingKey: string | undefined) {
  if (!bindingKey || !/^[A-Za-z0-9_-]{43}$/.test(bindingKey) || Buffer.from(bindingKey, "base64url").length !== 32)
    throw Error("PRIVATE_ACTOR_BINDING_KEY_REQUIRED");
  return createHmac("sha256", Buffer.from(bindingKey, "base64url"))
    .update("routecairn-profile-binding-v2\0")
    .update(JSON.stringify(canonical(authProfileSchema.parse(v))))
    .digest("hex");
}
export const actorWorkflowDigest = (v: unknown) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(z.array(workflowAuthorizationSchema).parse(v))))
    .digest("hex");
export const actorRegistryDigest = (v: ActorRegistry) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(actorRegistrySchema.parse(v))))
    .digest("hex");
export type ActorProfiles = Readonly<Record<string, AuthProfile>>;
export function validateActorRegistry(
  value: ActorRegistry,
  profiles: ActorProfiles,
  target: string,
  organization: string,
  bindingKey?: string
): ActorRegistry {
  const registry = actorRegistrySchema.parse(value);
  if (registry.targetOrigin !== new URL(target).origin || registry.organizationId !== organization)
    throw Error("ACTOR_REGISTRY_CONTEXT_REPLAY");
  for (const id of Object.keys(profiles))
    if (!registry.actors.some((a) => a.id === id && a.authentication.mechanism !== "ANONYMOUS"))
      throw Error("UNBOUND_ACTOR_CREDENTIAL");
  for (const a of registry.actors) {
    const auth = a.authentication,
      p = profiles[a.id];
    if (auth.mechanism === "ANONYMOUS") {
      if (p) throw Error("ANONYMOUS_CREDENTIAL");
      continue;
    }
    if (auth.availability !== "AVAILABLE") {
      if (p) throw Error("UNAVAILABLE_ACTOR_CREDENTIAL_SUPPLIED");
      continue;
    }
    if (!p || credentialDigest(p, bindingKey) !== auth.credentialDigest)
      throw Error("ACTOR_CREDENTIAL_EXPIRED_CHANGED_OR_MISSING");
    if (
      a.principalFingerprint !== (p.principalId ? identityFingerprint(p.principalId) : undefined) ||
      a.roleFingerprint !== (p.role ? identityFingerprint(p.role) : undefined) ||
      a.tenantFingerprint !== (p.tenantId ? identityFingerprint(p.tenantId) : undefined)
    )
      throw Error("ACTOR_DECLARATION_MISMATCH");
    for (const cookie of p.cookies)
      if (cookie.domain && cookie.domain.replace(/^\./, "") !== new URL(registry.targetOrigin).hostname)
        throw Error("ACTOR_COOKIE_ORIGIN_MISMATCH");
    if (
      p.browserBootstrap?.login?.startUrl &&
      new URL(p.browserBootstrap.login.startUrl).origin !== registry.targetOrigin
    )
      throw Error("THIRD_PARTY_LOGIN_WORKFLOW_NOT_AUTHORIZED");
    const identityFields = [
      p.identityVerification.principalIdField,
      p.identityVerification.roleField,
      p.identityVerification.tenantIdField
    ].filter((x): x is string => !!x);
    if (new Set(identityFields).size !== identityFields.length)
      throw Error("ACTOR_INDEPENDENT_IDENTITY_FIELDS_REQUIRED");
    const names = Object.keys(p.headers).map((k) => k.toLowerCase()),
      authorization = Object.entries(p.headers).find(([k]) => k.toLowerCase() === "authorization")?.[1];
    const matches =
      auth.mechanism === "BEARER"
        ? /^Bearer \S+/i.test(authorization ?? "")
        : auth.mechanism === "COOKIE"
          ? p.cookies.length > 0 || names.includes("cookie")
          : auth.mechanism === "API_KEY"
            ? names.some((n) => !["authorization", "user-agent", "accept", "content-type", "cookie"].includes(n))
            : !!p.browserBootstrap || p.cookies.length > 0;
    if (!matches) throw Error("ACTOR_AUTHENTICATION_MECHANISM_MISMATCH");
    if (p.identityVerification.endpoint) {
      const u = new URL(p.identityVerification.endpoint, registry.targetOrigin);
      if (u.origin !== registry.targetOrigin || u.username || u.password || u.search || u.hash)
        throw Error("ACTOR_IDENTITY_ORIGIN_MISMATCH");
    }
  }
  return registry;
}
export function actorProofMatches(
  registry: ActorRegistry,
  id: string,
  proof: IdentityVerificationResult | undefined,
  requirements: readonly ("PRINCIPAL" | "ROLE" | "TENANT")[],
  executionId?: string
): boolean {
  const a = registry.actors.find((a) => a.id === id);
  if (
    !a ||
    a.authentication.mechanism === "ANONYMOUS" ||
    a.authentication.availability !== "AVAILABLE" ||
    Date.parse(a.authentication.credentialExpiresAt) <= Date.now() ||
    !executionId ||
    proof?.identityExecutionId !== executionId ||
    proof.actorRegistryId !== registry.registryId ||
    proof.actorReference !== id ||
    proof.actorRegistryFingerprint !== actorRegistryDigest(registry) ||
    proof.actorCredentialBinding !== a.authentication.credentialDigest ||
    !proof?.verified ||
    !["VERIFIED", "VERIFIED_WITH_PARTIAL_METADATA"].includes(proof.category) ||
    proof.principalMatched !== true ||
    !a.principalFingerprint ||
    proof.principalHash !== a.principalFingerprint
  )
    return false;
  if (
    requirements.includes("ROLE") &&
    (!a.roleFingerprint || proof.roleMatched !== true || proof.roleHash !== a.roleFingerprint)
  )
    return false;
  if (
    requirements.includes("TENANT") &&
    (!a.tenantFingerprint || proof.tenantMatched !== true || proof.tenantHash !== a.tenantFingerprint)
  )
    return false;
  return true;
}
export async function loadActorRegistry(path: string, target: string, organization: string) {
  const b = await readBoundedActorFile(path);
  if (b.length > 262144) throw Error("ACTOR_REGISTRY_FILE_BOUND");
  const input = z
    .object({
      registry: actorRegistrySchema,
      bindingKey: z
        .string()
        .regex(/^[A-Za-z0-9_-]{43}$/)
        .optional(),
      profiles: z.record(z.string().min(1).max(1000))
    })
    .strict()
    .parse(JSON.parse(b.toString()));
  const profiles: Record<string, AuthProfile> = Object.create(null);
  for (const [id, p] of Object.entries(input.profiles))
    profiles[id] = parseAuthProfile((await readBoundedActorFile(resolve(dirname(path), p))).toString("utf8"));
  return {
    registry: validateActorRegistry(input.registry, profiles, target, organization, input.bindingKey),
    profiles,
    bindingKey: input.bindingKey
  };
}

async function readBoundedActorFile(path: string) {
  const handle = await open(path, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 262144) throw Error("ACTOR_REGISTRY_FILE_BOUND");
    const buffer = Buffer.alloc(262145);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    if (size > 262144) throw Error("ACTOR_REGISTRY_FILE_BOUND");
    return buffer.subarray(0, size);
  } finally {
    await handle.close();
  }
}
