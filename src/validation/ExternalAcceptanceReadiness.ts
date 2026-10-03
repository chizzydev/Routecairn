import { readBoundedFile } from "../core/files/BoundedFile.js";
import { createHash, createPublicKey } from "node:crypto";
import { lookup } from "node:dns/promises";

import { isIP } from "node:net";
import { resolve } from "node:path";
import { z } from "zod";
import type { ExternalAcceptanceManifest } from "./ExternalAcceptance.js";

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const file = z.object({ path: z.string().min(1).max(4096), sha256: hash }).strict();
export const externalAcceptanceBindingsSchema = z.object({
  schemaVersion: z.literal(1), authorizationProof: file,
  lanes: z.array(z.object({ id: z.string().min(1).max(100), reproduction: file, deployment: file }).strict()).length(8)
}).strict().refine((value) => new Set(value.lanes.map((lane) => lane.id)).size === 8, "Duplicate lane bindings");
export const externalAcceptanceTrustSchema = z.object({
  schemaVersion: z.literal(1), operators: z.array(z.object({
    keyId: hash, organization: z.string().min(2).max(160), publicKeyPem: z.string().min(40).max(4096),
    validFrom: z.string().datetime(), validUntil: z.string().datetime(), revoked: z.boolean(),
    independentlyVetted: z.literal(true), vettingReference: z.string().min(3).max(500)
  }).strict()).min(1).max(100)
}).strict().superRefine((value, ctx) => {
  const keys = new Set<string>();
  for (const operator of value.operators) {
    try {
      const key = createPublicKey(operator.publicKeyPem);
      if (key.asymmetricKeyType !== "ed25519" || acceptanceDigest(key.export({ type: "spki", format: "der" })) !== operator.keyId) throw new Error();
      if (keys.has(operator.keyId) || Date.parse(operator.validFrom) >= Date.parse(operator.validUntil)) throw new Error();
      keys.add(operator.keyId);
    } catch { ctx.addIssue({ code: "custom", message: "Invalid, duplicate or incorrectly attributed Ed25519 operator key." }); }
  }
});
export type ExternalAcceptanceBindings = z.infer<typeof externalAcceptanceBindingsSchema>;
export type ExternalAcceptanceTrust = z.infer<typeof externalAcceptanceTrustSchema>;
export interface AcceptanceReadiness {
  schemaVersion: 1; status: "READY" | "BLOCKED"; checkedAt: string; manifestSha256: string;
  issues: Array<{ code: string; location: string }>;
  lanes: Array<{ id: string; kind: string; status: "READY" | "BLOCKED" }>;
  credentialEnvironmentNames: string[]; requestBudget: number; cleanupActions: number;
  externalAcceptancePerformed: false; limitations: string[];
}

export async function acceptanceBoundFile(binding: z.infer<typeof file>): Promise<Buffer> {
  const bytes = await readBoundedFile(resolve(binding.path), 16 * 1024 * 1024);
  if (acceptanceDigest(bytes) !== binding.sha256) throw new Error("EXTERNAL_ACCEPTANCE_BOUND_FILE_DIGEST_MISMATCH");
  return bytes;
}

export function trustedAcceptanceOperator(trust: ExternalAcceptanceTrust, keyId: string, organization: string, at: string) {
  const parsed = externalAcceptanceTrustSchema.parse(trust);
  const operator = parsed.operators.find((item) => item.keyId === keyId && item.organization === organization);
  const time = Date.parse(at);
  if (!Number.isFinite(time) || !operator || operator.revoked || time < Date.parse(operator.validFrom) || time >= Date.parse(operator.validUntil)) throw new Error("EXTERNAL_ACCEPTANCE_OPERATOR_UNTRUSTED");
  return operator;
}

export function assertAcceptanceExternalOrigin(raw: string): void {
  const url = new URL(raw); const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash || host === "localhost" || /\.(?:localhost|test|invalid|example)$/.test(host) || /(?:^|\.)example\.(?:com|org|net)$/.test(host) || host.startsWith("127.") || ["0.0.0.0", "::", "::1", "project.supabase.co"].includes(host) || isIP(host) === 6 && /^::ffff:(?:7f[0-9a-f]{2}:|0:0$)/.test(host)) throw new Error("EXTERNAL_ACCEPTANCE_REAL_HTTPS_ORIGIN_REQUIRED");
}

export async function prepareExternalAcceptance(manifest: ExternalAcceptanceManifest, options: { bindings?: ExternalAcceptanceBindings; trust?: ExternalAcceptanceTrust; environment?: NodeJS.ProcessEnv; now?: Date; resolveDns?: boolean }): Promise<AcceptanceReadiness> {
  const now = (options.now ?? new Date()).toISOString();
  const issues: AcceptanceReadiness["issues"] = [];
  const issue = (code: string, location: string) => issues.push({ code, location });
  for (const code of acceptanceReferenceIssues(manifest)) issue(code, "manifest");
  const placeholder = /REPLACE(?:_WITH)?|CHANGEME|example\.(?:test|com|org|net)|OTHER_SYNTHETIC/i;
  const checkText = (value: string, location: string) => { if (placeholder.test(value)) issue("PLACEHOLDER_VALUE", location); };
  const checkHash = (value: string, location: string) => { if (/^(.)\1+$/.test(value)) issue("PLACEHOLDER_DIGEST", location); };
  checkText(manifest.operator.organization, "operator.organization"); checkText(manifest.operator.contact, "operator.contact");
  checkText(manifest.release.sourceRepository, "release.sourceRepository"); checkHash(manifest.release.gitCommit, "release.gitCommit"); checkHash(manifest.release.artifactSha256, "release.artifactSha256");
  checkText(manifest.authorization.authorizedBy, "authorization.authorizedBy"); checkText(manifest.authorization.proofReference, "authorization.proofReference"); checkHash(manifest.authorization.proofSha256, "authorization.proofSha256");
  if (Date.parse(now) < Date.parse(manifest.authorization.startsAt) || Date.parse(now) >= Date.parse(manifest.authorization.expiresAt)) issue("AUTHORIZATION_WINDOW_INACTIVE", "authorization");
  if (!options.trust) issue("INDEPENDENT_OPERATOR_TRUST_REQUIRED", "operator");
  else try { trustedAcceptanceOperator(options.trust, manifest.operator.publicKeyId, manifest.operator.organization, now); } catch { issue("INDEPENDENT_OPERATOR_UNTRUSTED", "operator"); }
  const environment = options.environment ?? process.env;
  for (const [alias, variable] of Object.entries(manifest.authorization.secretEnvironment)) if (typeof environment[variable] !== "string" || !environment[variable] || environment[variable]!.length > 65536) issue("CREDENTIAL_ENVIRONMENT_UNAVAILABLE", `authorization.secretEnvironment.${alias}`);
  for (const [alias, origin] of Object.entries(manifest.authorization.allowedOrigins)) {
    try {
      assertAcceptanceExternalOrigin(origin);
      if (options.resolveDns) {
        const host = new URL(origin).hostname.replace(/^\[|\]$/g, "");
        const answers = await lookup(host, { all: true });
        if (!answers.length) throw new Error();
        for (const answer of answers) assertAcceptanceExternalOrigin(`https://${answer.family === 6 ? `[${answer.address}]` : answer.address}`);
      }
    } catch { issue("REAL_EXTERNAL_ORIGIN_UNAVAILABLE", `authorization.allowedOrigins.${alias}`); }
  }
  if (!options.bindings) issue("AUTHORIZATION_AND_REPRODUCTION_BINDINGS_REQUIRED", "bindings");
  else {
    try {
      if (options.bindings.authorizationProof.sha256 !== manifest.authorization.proofSha256) throw new Error();
      await acceptanceBoundFile(options.bindings.authorizationProof);
    } catch { issue("AUTHORIZATION_PROOF_UNVERIFIED", "authorization"); }
  }
  const lanes: AcceptanceReadiness["lanes"] = [];
  for (const lane of manifest.lanes) {
    const start = issues.length; const location = `lanes.${lane.id}`;
    for (const [name, value] of Object.entries({ targetProduct: lane.targetProduct, targetVersion: lane.targetVersion, reproductionReference: lane.reproductionReference, paymentProvider: lane.paymentProvider ?? "" })) checkText(value, `${location}.${name}`);
    checkHash(lane.targetFingerprint, `${location}.targetFingerprint`); checkHash(lane.reproductionSha256, `${location}.reproductionSha256`);
    const binding = options.bindings?.lanes.find((item) => item.id === lane.id);
    if (!binding) issue("LANE_REPRODUCTION_AND_DEPLOYMENT_REQUIRED", location);
    else try {
      if (binding.reproduction.sha256 !== lane.reproductionSha256 || binding.deployment.sha256 !== lane.targetFingerprint) throw new Error();
      await acceptanceBoundFile(binding.reproduction); await acceptanceBoundFile(binding.deployment);
    } catch { issue("LANE_ARTIFACT_DIGEST_MISMATCH", location); }
    for (const action of lane.actions) if (action.semantic.startsWith("GRAPHQL_SUBSCRIPTION") && !action.request.transport) issue("NATIVE_SUBSCRIPTION_TRANSPORT_REQUIRED", `${location}.actions.${action.id}`);
    lanes.push({ id: lane.id, kind: lane.kind, status: start === issues.length ? "READY" : "BLOCKED" });
  }
  if (issues.some((item) => !item.location.startsWith("lanes."))) for (const lane of lanes) lane.status = "BLOCKED";
  return { schemaVersion: 1, status: issues.length ? "BLOCKED" : "READY", checkedAt: now, manifestSha256: acceptanceDigest(acceptanceCanonical(manifest)), issues, lanes, credentialEnvironmentNames: [...new Set(Object.values(manifest.authorization.secretEnvironment))].sort(), requestBudget: manifest.authorization.maxRequests, cleanupActions: manifest.lanes.reduce((sum, lane) => sum + lane.actions.filter((action) => action.phase === "CLEANUP").length, 0), externalAcceptancePerformed: false, limitations: ["Readiness performs no provider actions and is not acceptance evidence.", "Independent vetting and deployment/procedure ownership are established by the trust administrator; hashes establish file integrity."] };
}

export function acceptanceDigest(value: Buffer | string): string { return createHash("sha256").update(value).digest("hex"); }
export function acceptanceCanonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)])); return value; }

export function acceptanceReferenceIssues(manifest: ExternalAcceptanceManifest): string[] {
  const issues = new Set<string>();
  const reference = /\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/;
  const sensitive = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|apikey|password|secret|client_secret|access_token|refresh_token|id_token|api_key|signing_key|token|signature)$/i;
  const credentialCheck = (value: unknown): void => {
    if (Array.isArray(value)) for (const item of value) credentialCheck(item);
    else if (value && typeof value === "object") for (const [name, item] of Object.entries(value)) {
      if (sensitive.test(name) && typeof item === "string" && item && !reference.test(item)) issues.add("INLINE_CREDENTIAL_FORBIDDEN");
      credentialCheck(item);
    }
  };
  for (const lane of manifest.lanes) {
    const captures = new Set<string>();
    for (const action of [...lane.actions.filter((item) => item.phase !== "CLEANUP"), ...lane.actions.filter((item) => item.phase === "CLEANUP")]) {
      credentialCheck(action.request); credentialCheck(action.assertions);
      for (const match of action.request.path.matchAll(/[?&]([^=&]+)=([^&#]*)/g)) if (sensitive.test(match[1]!) && match[2] && !reference.test(match[2])) issues.add("INLINE_CREDENTIAL_FORBIDDEN");
      for (const match of JSON.stringify([action.request, action.assertions]).matchAll(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g)) {
        if (match[1] === "SECRET" ? !Object.hasOwn(manifest.authorization.secretEnvironment, match[2]!) : !captures.has(match[2]!)) issues.add("UNBOUND_SECRET_OR_CAPTURE_REFERENCE");
      }
      for (const name of Object.keys(action.captures)) captures.add(name);
    }
  }
  return [...issues];
}
