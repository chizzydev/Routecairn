import { legacyProductionCampaignSchema } from "../../core/authorization/ProductionCampaign.js";
import { actorRegistryDigest, loadActorRegistry } from "../../core/auth/ActorRegistry.js";
import { assertProductionRegistry } from "../../core/authorization/ProductionCampaign.js";
import { Command } from "commander";
import { z } from "zod";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { targetAuthorizationSchema } from "../../core/authorization/TargetAuthorization.js";
import { apiGraphqlInputSchema } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { OwnedTemporaryResource } from "../../core/storage/OwnedTemporaryResource.js";
import { exampleScope } from "../../config/defaults.js";
import { runScanCommand } from "./scan.js";
import { projectProductionDiscovery } from "../../intelligence/inventory/ProductionApplicationDiscovery.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
const fp = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
export const productionWebInputSchema = z
  .object({
    schemaVersion: z.literal(1),
    entryUrl: z.string().url().max(2048),
    authorization: targetAuthorizationSchema,
    browser: z.boolean(),
    apiGraphql: apiGraphqlInputSchema.optional(),
    sourceHints: z
      .array(z.object({ url: z.string().url().max(2048), sourceSha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict())
      .max(20)
  })
  .strict()
  .superRefine((v, c) => {
    const p = v.authorization.productionCampaign,
      u = new URL(v.entryUrl),
      fail = (message: string) => c.addIssue({ code: z.ZodIssueCode.custom, message });
    if (
      !p ||
      u.origin !== v.authorization.targetOrigin ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      !p.requests.some((r) => r.origin === u.origin && r.path === u.pathname && r.method === "GET")
    )
      fail("Exact entry GET must be approved by a production campaign");
    if (p?.authenticationPermitted && v.browser)
      fail(
        "Authenticated browser workflows require their own reviewed native bootstrap; this adapter is HTTP-only for authenticated campaigns"
      );
    for (const check of v.apiGraphql?.checks ?? [])
      if (
        !("request" in check) ||
        !("method" in check.request) ||
        !["GET", "HEAD", "OPTIONS"].includes(check.request.method) ||
        ("actorId" in check &&
          v.apiGraphql?.actors.find((a) => a.id === check.actorId)?.authSlot !== "anonymous" &&
          !check.requireVerifiedIdentity)
      )
        fail("Production checks require read-only exact native identity admission");
  });
export type ProductionWebInput = z.infer<typeof productionWebInputSchema>;
export const productionCampaignDigest = (v: ProductionWebInput) =>
  fp(JSON.stringify(productionWebInputSchema.parse(v)));
export type LegacyProductionWebInput = ProductionWebInput & {
  authorization: { productionCampaign: import("zod").infer<typeof legacyProductionCampaignSchema> };
};
export function prepareProductionWebCampaign(
  entryUrl: string,
  reference: string,
  now = Date.now()
): LegacyProductionWebInput {
  const url = new URL(entryUrl);
  if (url.username || url.password || url.search || url.hash) throw Error("PUBLIC_ENTRY_URL_REQUIRED");
  return productionWebInputSchema.parse({
    schemaVersion: 1,
    entryUrl: url.href,
    browser: false,
    sourceHints: [],
    authorization: {
      schemaVersion: 1,
      mode: "OWNED_PRODUCTION",
      targetOrigin: url.origin,
      proof: { reference, sha256: fp(reference) },
      productionCampaign: {
        campaignId: randomUUID(),
        program: "Owner reviewed production public application",
        platform: "OWNER_CONTROLLED",
        reportMode: "PRODUCTION_READ_ONLY",
        startsAt: new Date(now - 1000).toISOString(),
        expiresAt: new Date(now + 3600000).toISOString(),
        budgetScope: "PER_ASSESSMENT_RUN",
        maxRequests: 30,
        rateLimitPerSecond: 1,
        concurrency: 1,
        requestTimeoutMs: 15000,
        maxDurationMs: 180000,
        maxResponseBytes: 262144,
        inScope: [{ origin: url.origin, pathPrefix: "/" }],
        outOfScope: [{ origin: url.origin, pathPrefix: "/logout" }],
        rules: [
          "Only exact reviewed read-only requests and separately approved static assets",
          "Unknown endpoints and origins remain candidates, never automatic scope"
        ],
        prohibitedActions: [
          "No private customer records, guessed credentials, mutations, real payments, account provisioning or session reuse"
        ],
        requests: [
          {
            origin: url.origin,
            path: url.pathname,
            method: "GET",
            effect: "READ",
            expectedStatuses: [200, 301, 302, 307, 308]
          }
        ],
        staticAssets: [],
        workflows: ["PUBLIC_DISCOVERY", "PUBLIC_READ_ONLY"],
        authenticationPermitted: false,
        mutationPermitted: false,
        destructivePermitted: false,
        racePermitted: false,
        disposableAccountsSupplied: false,
        identities: [],
        effects: { sessionHousekeeping: "NONE_PUBLIC_UNAUTHENTICATED", approved: true },
        retention: {
          retainEvidence: true,
          rawBodiesInPortableReport: false,
          cleanup: "RETAIN_EVIDENCE_NO_AUTOMATIC_DELETION",
          stateChangingTests: "SEPARATE_REVERSIBLE_CONTRACT_REQUIRED"
        }
      }
    }
  }) as LegacyProductionWebInput;
}
export async function runProductionWebCampaign(
  value: unknown,
  approvedDigest: string,
  parent: string,
  options: {
    actorRegistry?: string;
    organization?: string;
    auth?: string;
    authA?: string;
    authB?: string;
    signal?: AbortSignal;
  } = {}
) {
  const input = productionWebInputSchema.parse(value),
    digest = productionCampaignDigest(input),
    p = input.authorization.productionCampaign!;
  if (approvedDigest !== digest) throw Error("PRODUCTION_CAMPAIGN_REVIEW_DIGEST_MISMATCH");
  if (!p.authenticationPermitted && (options.auth || options.authA || options.authB))
    throw Error("PRODUCTION_CAMPAIGN_CREDENTIALS_PROHIBITED");
  if (!("contractVersion" in p) && p.authenticationPermitted && (!options.auth || !options.authA || !options.authB))
    throw Error("PRODUCTION_CAMPAIGN_THREE_FRESH_IDENTITIES_REQUIRED");
  const actorSet = options.actorRegistry
    ? await loadActorRegistry(resolve(options.actorRegistry), input.entryUrl, options.organization ?? "")
    : undefined;
  assertProductionRegistry(
    p,
    actorSet?.registry,
    actorSet?.profiles,
    options.organization,
    input.entryUrl,
    actorSet?.bindingKey
  );
  const owned = OwnedTemporaryResource.create(resolve(parent), {
      purpose: "production-web-assessment",
      campaignId: p.campaignId,
      digest
    }),
    root = owned.root;
  const save = (name: string, v: unknown) => {
    const path = join(root, name);
    writeFileSync(path, JSON.stringify(v, null, 2), { flag: "wx" });
    return path;
  };
  const controller = new AbortController(),
    timer = setTimeout(() => controller.abort(), p.maxDurationMs),
    signal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;
  try {
    save("campaign.json", input);
    save("review.json", {
      digest,
      approvedDigest,
      approvedAt: new Date().toISOString(),
      effects: p.effects,
      stateChangingExecution: "HOLD"
    });
    const scope = save("scope.json", {
      ...exampleScope,
      program: p.program,
      allowedDomains: [...new Set(p.inScope.map((a) => new URL(a.origin).hostname))],
      includeSubdomains: false,
      sameOriginOnly: p.inScope.every((a) => a.origin === input.authorization.targetOrigin),
      allowedMethods: ["GET", "HEAD", "OPTIONS"],
      rateLimitPerSecond: p.rateLimitPerSecond,
      concurrency: p.concurrency,
      maxDepth: 0,
      disallowedPaths: []
    });
    const config = save("config.json", {
      reportsDir: join(root, "reports"),
      bodyPreviewBytes: p.maxResponseBytes,
      requestTimeoutMs: p.requestTimeoutMs,
      nextJsReview: {
        inspectNextJsSourceMaps: false,
        inspectKnownNextJsDataSurfaces: false,
        nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW",
        maxNextJsManifestRequests: 2,
        maxNextJsDataSurfaceRequests: 1,
        maxNextJsSourceMapRequests: 1,
        maxNextJsCacheDifferentialRequests: 0,
        maxNextJsAssetsInspected: 64,
        maxNextJsRoutesProcessed: 128
      }
    });
    const authorization = save("authorization.json", input.authorization);
    const api =
      input.apiGraphql ??
      (actorSet
        ? flexiblePublicChecks(input, actorSet.registry)
        : apiGraphqlInputSchema.parse({
            maxRequests: Math.min(300, p.maxRequests),
            maxResponseBytes: Math.min(524288, p.maxResponseBytes),
            actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }],
            routes: p.requests.map((r, i) => ({
              id: "campaign-control-" + i,
              safeAlias: "campaign-control-" + i,
              protocol: "REST",
              kind: "FUNCTION",
              functionName: "approved-public-http-control",
              url: r.origin + r.path,
              documentedMethods: [r.method]
            })),
            checks: p.requests.map((r, i) => ({
              id: "campaign-control-" + i,
              matrixId: "campaign-control-" + i,
              label: "Owner reviewed public HTTP status observation",
              kind: "FUNCTION_AUTHORIZATION",
              routeId: "campaign-control-" + i,
              actorId: "public",
              requireVerifiedIdentity: false,
              request: { method: r.method },
              response: { expectedDecision: "OBSERVE" }
            }))
          }));
    const apiPath = save("native-checks.json", api);
    const result = await runScanCommand(
      input.entryUrl,
      {
        scope,
        config,
        targetAuthorization: authorization,
        apiGraphql: apiPath,
        profile: "quick",
        includeModules: [
          "baseline",
          "tech-fingerprint",
          "header-review",
          "cookie-review",
          "js-intelligence",
          "nextjs-review",
          ...(input.browser ? ["browser-crawler" as const] : [])
        ],
        replaceProfileModules: true,
        maxRequests: String(p.maxRequests),
        rate: String(p.rateLimitPerSecond),
        concurrency: String(p.concurrency),
        cleanupReservedRequests: "0",
        output: join(root, "reports"),
        historyDirectory: join(root, "history"),
        suppressProcessExitCode: true,
        ...(actorSet ? { actorRegistry: options.actorRegistry!, organization: options.organization! } : {}),
        ...(options.auth ? { auth: options.auth } : {}),
        ...(options.authA ? { authA: options.authA } : {}),
        ...(options.authB ? { authB: options.authB } : {})
      },
      signal
    );
    const bytes = readFileSync(result.reportPath),
      report = JSON.parse(bytes.toString()) as RouteCairnReport;
    const assessment = projectProductionDiscovery(report, input.authorization, fp(bytes), input.sourceHints);
    save("assessment.json", { ...assessment, campaignDigest: digest });
    save("retention.json", {
      root,
      sourceReportSha256: fp(bytes),
      status: result.status,
      cancelled: signal.aborted,
      rawEvidencePublic: false,
      automaticCleanup: false
    });
    return { root, campaignDigest: digest, status: result.status, assessment };
  } catch (error) {
    save("failure.json", {
      state: "UNKNOWN_OR_FAILED",
      reason: error instanceof Error ? error.name : "Unknown",
      message: "No replay or security pass inferred. Inspect retained private native evidence.",
      campaignDigest: digest
    });
    throw error;
  } finally {
    clearTimeout(timer);
    owned.retain("PRODUCTION_ASSESSMENT_EVIDENCE_RETAINED");
  }
}
export function registerWebAssessmentCommand(program: Command) {
  const command = program
    .command("web-assessment")
    .description("Prepare and execute exact reviewed production campaigns through the existing native engine");
  command
    .command("prepare")
    .argument("<entry-url>")
    .requiredOption("--reference <reference>", "Owner authorization reference")
    .requiredOption("--output <file>", "New draft file")
    .option("--actor-registry <file>", "Private version-2 registry and profile references")
    .option("--organization <id>", "Exact registry organization")
    .action(
      async (
        entry: string,
        o: { reference: string; output: string; actorRegistry?: string; organization?: string }
      ) => {
        const campaign = o.actorRegistry
          ? await prepareRegistryProductionCampaign(entry, o.reference, o.actorRegistry, o.organization ?? "")
          : prepareProductionWebCampaign(entry, o.reference);
        writeFileSync(resolve(o.output), JSON.stringify(campaign, null, 2), { flag: "wx" });
        console.log("DRAFT_ONLY_NO_REQUESTS");
      }
    );
  command
    .command("review")
    .requiredOption("--campaign <file>", "Exact edited campaign JSON")
    .action((o: { campaign: string }) => {
      const bytes = readFileSync(resolve(o.campaign));
      if (bytes.length > 262144) throw Error("CAMPAIGN_FILE_BOUND");
      const input = productionWebInputSchema.parse(JSON.parse(bytes.toString()));
      console.log(
        JSON.stringify(
          {
            state: "OWNER_APPROVAL_REQUIRED_NO_REQUESTS",
            digest: productionCampaignDigest(input),
            campaign: input.authorization.productionCampaign,
            browser: input.browser
              ? "Expiring HTTPS tunnel remains blocked; HTTP-only native browser observation may be available"
              : "NOT_REQUESTED",
            candidateOriginsNeverAuthorized: true
          },
          null,
          2
        )
      );
    });
  command
    .command("run")
    .requiredOption("--campaign <file>", "Reviewed campaign JSON (not the draft envelope)")
    .requiredOption("--approved-digest <sha256>", "Digest of the exact reviewed campaign")
    .requiredOption("--output-parent <directory>", "Parent for a new owned retained run directory")
    .option("--actor-registry <file>", "Version-2 registry with private profile references")
    .option("--organization <id>", "Exact registry organization")
    .option("--auth <file>", "Fresh primary profile")
    .option("--auth-a <file>", "Fresh account A profile")
    .option("--auth-b <file>", "Fresh account B profile")
    .action(
      async (o: {
        campaign: string;
        approvedDigest: string;
        outputParent: string;
        actorRegistry?: string;
        organization?: string;
        auth?: string;
        authA?: string;
        authB?: string;
      }) => {
        const path = resolve(o.campaign),
          bytes = readFileSync(path);
        if (bytes.length > 262144) throw Error("CAMPAIGN_FILE_BOUND");
        const controller = new AbortController(),
          stop = () => controller.abort();
        process.once("SIGINT", stop);
        try {
          const r = await runProductionWebCampaign(JSON.parse(bytes.toString()), o.approvedDigest, o.outputParent, {
            ...o,
            signal: controller.signal
          });
          console.log(JSON.stringify(r));
          if (r.status !== "COMPLETED") process.exitCode = 2;
        } finally {
          process.off("SIGINT", stop);
        }
      }
    );
}

function flexiblePublicChecks(
  input: ProductionWebInput,
  registry: import("../../core/auth/ActorRegistry.js").ActorRegistry
) {
  const p = input.authorization.productionCampaign!;
  let publicId = "public";
  while (registry.actors.some((a) => a.id === publicId)) publicId += "0";
  const actors = [
    { id: publicId, safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" },
    ...registry.actors
      .filter((a) => a.authentication.mechanism !== "ANONYMOUS")
      .map((a) => ({ id: a.id, safeAlias: a.label, authSlot: "registry", relationship: "OWNER_REVIEWED_TEST_ACTOR" }))
  ];
  const checks: unknown[] = [];
  let n = 0;
  for (const [i, r] of p.requests.entries())
    for (const w of registry.workflows) {
      const ids =
        w.family === "PUBLIC_OBSERVATION" ? [publicId] : w.family === "AUTHENTICATED_OBSERVATION" ? w.actorIds : [];
      for (const actorId of ids)
        checks.push({
          id: "campaign-observe-" + n++,
          matrixId: w.id,
          label: "Reviewed native HTTP observation",
          kind: "FUNCTION_AUTHORIZATION",
          routeId: "campaign-control-" + i,
          actorId,
          requireVerifiedIdentity: false,
          request: { method: r.method },
          response: { expectedDecision: "OBSERVE" }
        });
    }
  return apiGraphqlInputSchema.parse({
    maxRequests: p.maxRequests,
    maxResponseBytes: Math.min(524288, p.maxResponseBytes),
    actors,
    routes: p.requests.map((r, i) => ({
      id: "campaign-control-" + i,
      safeAlias: "campaign-control-" + i,
      protocol: "REST",
      kind: "FUNCTION",
      functionName: "reviewed-native-control",
      url: r.origin + r.path,
      documentedMethods: [r.method]
    })),
    checks
  });
}

export async function prepareRegistryProductionCampaign(
  entry: string,
  reference: string,
  path: string,
  organization: string
): Promise<ProductionWebInput> {
  const source = await loadActorRegistry(resolve(path), entry, organization),
    old = prepareProductionWebCampaign(entry, reference),
    { identities: _, disposableAccountsSupplied: __, ...common } = old.authorization.productionCampaign;
  const authenticated = source.registry.actors.some((a) => a.authentication.mechanism !== "ANONYMOUS"),
    requests = [...common.requests];
  for (const p of Object.values(source.profiles)) {
    if (!p.identityVerification.endpoint) continue;
    const u = new URL(p.identityVerification.endpoint, entry);
    if (!requests.some((r) => r.origin === u.origin && r.path === u.pathname))
      requests.push({
        origin: u.origin,
        path: u.pathname,
        method: "GET",
        effect: "READ",
        expectedStatuses: [200, 401, 403]
      });
  }
  return productionWebInputSchema.parse({
    ...old,
    authorization: {
      ...old.authorization,
      productionCampaign: {
        ...common,
        contractVersion: 2,
        requests,
        actorRegistryDigest: actorRegistryDigest(source.registry),
        actorIds: source.registry.actors.filter((a) => a.authentication.mechanism !== "ANONYMOUS").map((a) => a.id),
        workflowAuthorizations: source.registry.workflows,
        authenticationPermitted: authenticated,
        workflows: [authenticated ? "AUTHENTICATED_READ_ONLY" : "PUBLIC_READ_ONLY"],
        effects: {
          sessionHousekeeping: authenticated ? "SESSION_LAST_USED_AT_UPDATE" : "NONE_PUBLIC_UNAUTHENTICATED",
          approved: true
        }
      }
    }
  });
}
