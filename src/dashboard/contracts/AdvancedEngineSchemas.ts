import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { targetAuthorizationSchema } from "../../core/authorization/TargetAuthorization.js";
import { apiGraphqlInputSchema } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { protocolSecurityInputSchema } from "../../modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { assistedReviewInputSchema } from "../../modules/assistedReview/AssistedReviewPlanner.js";
import { authenticationLifecycleInputSchema } from "../../modules/authenticationLifecycle/AuthenticationLifecyclePlanner.js";
import { browserLearnedLifecycleAutomationInputSchema } from "../../modules/authenticationLifecycle/BrowserLearnedLifecycleCompiler.js";
import { billingEntitlementInputSchema } from "../../modules/billingEntitlement/BillingEntitlementPlanner.js";
import { businessInvariantInputSchema } from "../../modules/businessInvariant/BusinessInvariantPlanner.js";
import { controlledRaceInputSchema } from "../../modules/controlledRace/ControlledRacePlanner.js";
import { linkPortalSecurityInputSchema } from "../../modules/linkPortalSecurity/LinkPortalSecurityPlanner.js";
import { operationalEndpointSecurityInputSchema } from "../../modules/operationalEndpointSecurity/OperationalEndpointSecurityPlanner.js";
import { preHandoverInputSchema } from "../../modules/preHandover/PreHandoverPlanner.js";
import { supabaseAuthorizationInputSchema } from "../../modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";
import { activeVulnerabilityInputSchema } from "../../modules/activeVulnerability/ActiveVulnerabilityPlanner.js";

export const advancedEngineIds = [
  "supabase-authorization",
  "authentication-lifecycle",
  "authentication-lifecycle-automation",
  "business-invariant",
  "controlled-race",
  "api-graphql-authorization",
  "protocol-security",
  "link-portal-export-security",
  "operational-endpoint-security",
  "billing-entitlement-security",
  "assisted-review",
  "pre-handover-assault",
  "bug-bounty-authorization",
  "active-vulnerability-validation"
] as const;

export type AdvancedEngineId = typeof advancedEngineIds[number];

export interface AdvancedEngineCatalogEntry {
  id: AdvancedEngineId;
  displayName: string;
  description: string;
  moduleId?: string | undefined;
  requestField: string;
  templateFile: string;
  safety: string;
  requiresApproval: boolean;
}

export const advancedEngineCatalog: readonly AdvancedEngineCatalogEntry[] = [
  { id: "supabase-authorization", displayName: "Supabase / PostgREST / RLS / Storage", description: "Build actor-by-resource authorization cases and the expected database, function, relationship, and bucket catalog.", moduleId: "supabase-authorization", requestField: "supabaseAuthorization", templateFile: "supabase-authorization.example.json", safety: "Keys remain environment or vault references. Mutations still require an exact controlled-mutation contract.", requiresApproval: true },
  { id: "authentication-lifecycle", displayName: "Authentication lifecycle", description: "Define actors, lifecycle actions, captures, assertions, cleanup, and comparison semantics.", moduleId: "authentication-lifecycle", requestField: "authenticationLifecycle", templateFile: "authentication-lifecycle.example.json", safety: "State-changing cases require expiring authorization and disposable accounts.", requiresApproval: true },
  { id: "authentication-lifecycle-automation", displayName: "Learned authentication automation", description: "Choose which browser-learned login/session recipes may be compiled into explicit lifecycle cases.", moduleId: "authentication-lifecycle", requestField: "authenticationLifecycleAutomation", templateFile: "authentication-lifecycle-automation.example.json", safety: "Learning never grants mutation authority; this policy carries its own expiring approval.", requiresApproval: true },
  { id: "business-invariant", displayName: "Business invariants and state machines", description: "Model pre-state, actions, authoritative post-state, invariants, transitions, and verified restoration.", moduleId: "business-invariant", requestField: "businessInvariant", templateFile: "business-invariants.example.json", safety: "Every mutation is bounded to disposable entities and cleanup is mandatory.", requiresApproval: true },
  { id: "controlled-race", displayName: "Controlled race groups", description: "Build two-to-five request barriers with post-state, event-count, and cleanup invariants.", moduleId: "controlled-race", requestField: "controlledRace", templateFile: "controlled-races.example.json", safety: "This is bounded concurrency, never load testing.", requiresApproval: true },
  { id: "api-graphql-authorization", displayName: "API and GraphQL authorization", description: "Inventory routes, actors, authorization matrices, GraphQL operations, field rules, and version boundaries.", moduleId: "api-graphql-authorization", requestField: "apiGraphql", templateFile: "api-graphql.example.json", safety: "Only explicit operations are sent; discovery does not imply mutation authority.", requiresApproval: false },
  { id: "protocol-security", displayName: "Protocol-level security", description: "Validate WebSocket, SSE, GraphQL mutation/subscription, gRPC, multipart, HTTP/2, and HTTP/3 contracts.", moduleId: "protocol-security", requestField: "protocolSecurity", templateFile: "protocol-security.example.json", safety: "Streams are bounded; state changes and desynchronization require expiring non-production approval.", requiresApproval: true },
  { id: "link-portal-export-security", displayName: "Signed links, portals, invites, and exports", description: "Configure capability resources, actors, replay/tamper cases, ownership checks, and revocation cleanup.", moduleId: "link-portal-export-security", requestField: "linkPortalSecurity", templateFile: "link-portal-security.example.json", safety: "Capability values and identifiers remain worker-local and redacted.", requiresApproval: true },
  { id: "operational-endpoint-security", displayName: "Webhooks, cron, jobs, and operational endpoints", description: "Inventory operational endpoints and define signature, replay, ordering, authorization, and exposure checks.", moduleId: "operational-endpoint-security", requestField: "operationalEndpointSecurity", templateFile: "operational-endpoints.example.json", safety: "State-changing operational flows require exact approval and cleanup.", requiresApproval: true },
  { id: "billing-entitlement-security", displayName: "Synthetic billing and entitlement", description: "Build test-provider checkout, synthetic event, entitlement, cancellation, refund, and ownership cases.", moduleId: "billing-entitlement-security", requestField: "billingEntitlement", templateFile: "billing-entitlement.example.json", safety: "Real payment execution is forbidden by schema and runtime.", requiresApproval: true },
  { id: "assisted-review", displayName: "Assisted review inventory", description: "Select review lanes, case inventory, identity requirements, and completion gates.", moduleId: "assisted-review", requestField: "assistedReview", templateFile: "assisted-review.example.json", safety: "Human review remains mandatory before customer-safe publication.", requiresApproval: false },
  { id: "pre-handover-assault", displayName: "Pre-handover assault orchestration", description: "Bind disposable accounts, objects, invariants, races, sequencing, regressions, and review gates.", requestField: "preHandover", templateFile: "pre-handover.example.json", safety: "Only local, test, and staging environments are accepted.", requiresApproval: true },
  { id: "bug-bounty-authorization", displayName: "Bug-bounty authorization and scope rules", description: "Capture authorization proof, assets, exclusions, rules, testing window, rate budget, and exact request permissions.", requestField: "targetAuthorization", templateFile: "bug-bounty-authorization.example.json", safety: "Mutation and destructive access remain denied unless explicitly authorized and bound.", requiresApproval: true },
  { id: "active-vulnerability-validation", displayName: "Active vulnerability validation", description: "Compile safe candidates and execute proof-gated SQL/NoSQL injection, XSS, SSRF, command/template injection, traversal, CSRF, redirects, cache, deserialization, XXE, and desynchronization cases.", moduleId: "active-vulnerability-validation", requestField: "activeVulnerability", templateFile: "active-vulnerability-validation.example.json", safety: "Safe query probes can be automated. Stateful, callback, command, cache-poisoning, and raw-protocol proof retains explicit authorization gates.", requiresApproval: true }
] as const;

const schemaById: Record<AdvancedEngineId, z.ZodTypeAny> = {
  "supabase-authorization": supabaseAuthorizationInputSchema,
  "authentication-lifecycle": authenticationLifecycleInputSchema,
  "authentication-lifecycle-automation": browserLearnedLifecycleAutomationInputSchema,
  "business-invariant": businessInvariantInputSchema,
  "controlled-race": controlledRaceInputSchema,
  "api-graphql-authorization": apiGraphqlInputSchema,
  "protocol-security": protocolSecurityInputSchema,
  "link-portal-export-security": linkPortalSecurityInputSchema,
  "operational-endpoint-security": operationalEndpointSecurityInputSchema,
  "billing-entitlement-security": billingEntitlementInputSchema,
  "assisted-review": assistedReviewInputSchema,
  "pre-handover-assault": z.object({
    orchestration: preHandoverInputSchema,
    authorization: targetAuthorizationSchema.refine((value) => value.mode === "PRE_HANDOVER_ASSAULT", "Pre-handover execution requires PRE_HANDOVER_ASSAULT target authorization.")
  }).strict(),
  "bug-bounty-authorization": targetAuthorizationSchema,
  "active-vulnerability-validation": activeVulnerabilityInputSchema
};

export const advancedEngineValidationRequestSchema = z.object({
  engineId: z.enum(advancedEngineIds),
  value: z.unknown()
}).strict();

export function validateAdvancedEngineInput(engineId: AdvancedEngineId, value: unknown): { valid: boolean; value?: unknown; diagnostics: Array<{ path: string[]; message: string }> } {
  const parsed = schemaById[engineId].safeParse(value);
  if (!parsed.success) return { valid: false, diagnostics: parsed.error.issues.map((issue) => ({ path: issue.path.map(String), message: issue.message })) };
  return { valid: true, value: parsed.data, diagnostics: [] };
}

export async function loadAdvancedEngineCatalog(target?: string): Promise<Array<Omit<AdvancedEngineCatalogEntry, "templateFile"> & { template: unknown }>> {
  const origin = safeOrigin(target);
  const now = Date.now();
  const startsAt = new Date(now - 5 * 60_000).toISOString();
  const expiresAt = new Date(now + 4 * 60 * 60_000).toISOString();
  return Promise.all(advancedEngineCatalog.map(async ({ templateFile, ...entry }) => {
    const path = fileURLToPath(new URL(`../../../examples/${templateFile}`, import.meta.url));
    const raw = JSON.parse((await readFile(path, "utf8")).replace(/^\uFEFF/, "")) as unknown;
    const transformed = transformTemplate(raw, origin, startsAt, expiresAt);
    const retargeted = entry.id === "pre-handover-assault"
      ? { orchestration: transformed, authorization: preHandoverAuthorization(origin) }
      : transformed;
    const parsed = schemaById[entry.id].parse(retargeted);
    return { ...entry, template: parsed };
  }));
}

function preHandoverAuthorization(origin: string): z.input<typeof targetAuthorizationSchema> {
  return {
    schemaVersion: 1,
    mode: "PRE_HANDOVER_ASSAULT",
    targetOrigin: origin,
    proof: {
      reference: "Replace with the approved pre-handover authorization reference",
      sha256: "0".repeat(64)
    }
  };
}

function transformTemplate(value: unknown, origin: string, startsAt: string, expiresAt: string, key = ""): unknown {
  if (Array.isArray(value)) return value.map((item) => transformTemplate(item, origin, startsAt, expiresAt, key));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, transformTemplate(child, origin, startsAt, expiresAt, childKey)]));
  if (typeof value !== "string") return value;
  if (key === "authorizedAt" || key === "startsAt") return startsAt;
  if (key === "expiresAt") return expiresAt;
  return value.replaceAll("https://app.example.com", origin).replaceAll("https://your-project.supabase.co", origin);
}

function safeOrigin(target?: string): string {
  try { return target ? new URL(target).origin : "https://authorized-target.invalid"; }
  catch { return "https://authorized-target.invalid"; }
}
