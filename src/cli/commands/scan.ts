import { Command } from "commander";
import { dirname, resolve } from "node:path";
import { routeCairnConfigSchema, scanModeSchema, type ScanMode } from "../../config/ConfigSchema.js";
import { profileNames, resolveScanProfile, type ScanProfile, type ScanProfileName } from "../../config/ScanProfiles.js";
import { defaultConfig } from "../../config/defaults.js";
import { loadRouteCairnConfig, loadScope } from "../../config/loadConfig.js";
import { RouteCairnEngine, type ScanResult } from "../../core/engine/RouteCairnEngine.js";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";
import { createDefaultPluginRegistry } from "../../core/engine/ScanOrchestrator.js";
import { loadAuthProfile } from "../../core/auth/AuthProfile.js";
import { loadAuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { createLogger } from "../../core/logging/Logger.js";
import { ScanPlanner } from "../../core/planning/ScanPlanner.js";
import type { ModuleId, ModuleSettings } from "../../core/planning/ScanPlan.js";
import { loadFieldExposureInput, planFieldExposureTesting } from "../../modules/fieldExposureTesting/FieldExposurePlanner.js";
import { loadObjectPairInput, planObjectPairTesting } from "../../modules/objectPairTesting/ObjectPairPlanner.js";
import { loadAuthorizationMatrixInput, planAuthorizationMatrixTesting } from "../../modules/authorizationMatrix/AuthorizationMatrixPlanner.js";
import { loadCollectionAuthorizationInput, planCollectionAuthorizationTesting } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { loadBulkAuthorizationInput, planBulkAuthorizationTesting } from "../../modules/bulkAuthorization/BulkAuthorizationPlanner.js";
import { loadFileAuthorizationInput, planFileAuthorizationTesting } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";
import { loadEquivalentRouteInput, planEquivalentRouteTesting } from "../../modules/equivalentRouteTesting/EquivalentRoutePlanner.js";
import { loadSupabaseAuthorizationInput, planSupabaseAuthorization } from "../../modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";
import { loadAuthenticationLifecycleInput, planAuthenticationLifecycle } from "../../modules/authenticationLifecycle/AuthenticationLifecyclePlanner.js";
import { loadBrowserLearnedLifecycleAutomationInput, planBrowserLearnedLifecycleAutomation } from "../../modules/authenticationLifecycle/BrowserLearnedLifecycleCompiler.js";
import { loadBusinessInvariantInput, planBusinessInvariant } from "../../modules/businessInvariant/BusinessInvariantPlanner.js";
import { loadControlledRaceInput, planControlledRace } from "../../modules/controlledRace/ControlledRacePlanner.js";
import { loadApiGraphqlInput, planApiGraphqlReview } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { loadProtocolSecurityInput, planProtocolSecurity } from "../../modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { loadLinkPortalSecurityInput, planLinkPortalSecurity } from "../../modules/linkPortalSecurity/LinkPortalSecurityPlanner.js";
import { loadOperationalEndpointSecurityInput, planOperationalEndpointSecurity } from "../../modules/operationalEndpointSecurity/OperationalEndpointSecurityPlanner.js";
import { loadBillingEntitlementInput, planBillingEntitlement } from "../../modules/billingEntitlement/BillingEntitlementPlanner.js";
import { loadAssistedReviewInput, planAssistedReview } from "../../modules/assistedReview/AssistedReviewPlanner.js";
import { planPreHandover } from "../../modules/preHandover/PreHandoverPlanner.js";
import { targetAuthorizationSchema } from "../../core/authorization/TargetAuthorization.js";
import { privilegeMutationInputSchema, planPrivilegeMutationTesting } from "../../modules/privilegeMutation/PrivilegeMutationPlanner.js";
import { readFile } from "node:fs/promises";
import { controlledMutationContractSchema } from "../../core/offensive/ControlledMutationTypes.js";
import { loadReport } from "../../reports/ReportSummary.js";
import { entryFromReport, recordScan, scanIndexPath, timestampedOutputDir } from "../../storage/ScanIndex.js";
import { loadActiveVulnerabilityInput, planActiveVulnerabilityValidation } from "../../modules/activeVulnerability/ActiveVulnerabilityPlanner.js";
import { loadSafeInventoryImport } from "../../intelligence/inventory/SafeInventoryImporter.js";
import { reserveInventoryAcquisitionBudget, resolveSafeInventoryImport } from "../../intelligence/inventory/LiveInventoryResolver.js";

const logger = createLogger();

export interface ScanCommandOptions {
  scope?: string;
  mode?: string;
  profile?: string;
  rate?: string;
  concurrency?: string;
  maxRequests?: string;
  cleanupReservedRequests?: string;
  output?: string;
  config?: string;
  auth?: string;
  authA?: string;
  authB?: string;
  objectPairs?: string;
  fieldExposure?: string;
  authorizationMatrix?: string;
  collectionAuthorization?: string;
  bulkAuthorization?: string;
  fileAuthorization?: string;
  equivalentRoutes?: string;
  privilegeMutation?: string;
  mutationContracts?: string;
  supabaseAuthorization?: string;
  authenticationLifecycle?: string;
  authenticationLifecycleAuto?: string;
  businessInvariants?: string;
  controlledRaces?: string;
  apiGraphql?: string;
  protocolSecurity?: string;
  linkPortalSecurity?: string;
  operationalEndpoints?: string;
  billingEntitlement?: string;
  secretBoundary?: boolean;
  assistedReview?: string;
  preHandover?: string;
  targetAuthorization?: string;
  activeVulnerability?: string;
  inventoryImport?: string;
  /** Internal bounded module selection used by the signed native worker. */
  includeModules?: ModuleId[];
  /** Internal flag for module jobs that must not inherit a profile's module set. */
  replaceProfileModules?: boolean;
  /** Internal directory for the scan-history index. Used to contain remote-worker writes. */
  historyDirectory?: string;
  /** Internal flag for embedded callers that own their own process lifecycle. */
  suppressProcessExitCode?: boolean;
}

export function registerScanCommand(program: Command): void {
  program
    .command("scan")
    .description("Run a scoped RouteCairn scan against an authorized target.")
    .argument("<target>", "Target URL to scan.")
    .requiredOption("--scope <file>", "Path to a RouteCairn scope JSON file.")
    .option("--mode <mode>", "Scan mode for this run. Kept for compatibility; profiles are preferred for normal use.")
    .option("--profile <profile>", `Scan profile: ${profileNames().join(", ")}.`)
    .option("--rate <number>", "Override requests per second from the scope file.")
    .option("--concurrency <number>", "Override concurrency from the scope file.")
    .option("--max-requests <number>", "Set the authoritative scan-wide physical request budget.")
    .option("--cleanup-reserved-requests <number>", "Reserve part of the total request budget exclusively for cleanup/restoration.")
    .option("--output <dir>", "Directory where report.json should be written.")
    .option("--config <file>", "Path to routecairn.config.json.", "./routecairn.config.json")
    .option("--auth <file>", "Path to a RouteCairn auth profile JSON for authenticated comparison.")
    .option("--auth-a <file>", "Path to Account A auth profile JSON for role comparison.")
    .option("--auth-b <file>", "Path to Account B auth profile JSON for role comparison.")
    .option("--object-pairs <file>", "Path to an explicit object-pair testing JSON file.")
    .option("--field-exposure <file>", "Path to an explicit controlled field-exposure testing JSON file.")
    .option("--authorization-matrix <file>", "Path to an explicit controlled authorization matrix testing JSON file.")
    .option("--collection-authorization <file>", "Path to an explicit controlled collection authorization testing JSON file.")
    .option("--bulk-authorization <file>", "Path to an explicit controlled bulk authorization testing JSON file.")
    .option("--file-authorization <file>", "Path to an explicit controlled file authorization testing JSON file.")
    .option("--equivalent-routes <file>", "Path to an explicit controlled equivalent-route testing JSON file.")
    .option("--privilege-mutation <file>", "Path to an explicit authorized privilege/mass-assignment mutation plan.")
    .option("--mutation-contracts <file>", "Path to exact expiring controlled-mutation contracts.")
    .option("--supabase-authorization <file>", "Path to an explicit Supabase/PostgREST/RLS authorization manifest.")
    .option("--authentication-lifecycle <file>", "Path to an explicit authorized authentication lifecycle manifest.")
    .option("--authentication-lifecycle-auto <file>", "Learn login traffic and automatically compile and execute approved lifecycle cases from an automation policy.")
    .option("--business-invariants <file>", "Path to an explicit authorized business-invariant manifest.")
    .option("--controlled-races <file>", "Path to an explicit authorized synchronized race-testing manifest.")
    .option("--api-graphql <file>", "Path to an explicit API and GraphQL authorization review manifest.")
    .option("--protocol-security <file>", "Path to a bounded protocol-level security manifest.")
    .option("--link-portal-security <file>", "Path to an explicit signed-link, invite, portal, export, and artifact security manifest.")
    .option("--operational-endpoints <file>", "Path to an explicit webhook, cron, job, incident, health, admin, and worker endpoint security manifest.")
    .option("--billing-entitlement <file>", "Path to an explicit synthetic checkout, billing, entitlement, subscription, and premium-flow security manifest.")
    .option("--secret-boundary", "Enable automated client/server secret-boundary and sensitive-exposure correlation.")
    .option("--assisted-review <file>", "Append an explicit Assisted Trust & Security Review case inventory and completion gate.")
    .option("--pre-handover <file>", "Run an explicit disposable pre-handover registry and sequence; requires the pre-handover profile.")
    .option("--target-authorization <file>", "Exact target authorization mode and, for bug bounty, enforceable program permissions.")
    .option("--active-vulnerability <file>", "Path to a bounded active-vulnerability validation manifest (dashboard builder is preferred).")
    .option("--inventory-import <file>", "Import or safely acquire bounded OpenAPI, Postman, HAR, GraphQL, Supabase, and live service inventory.")
    .action(async (target: string, options: ScanCommandOptions) => {
      const controller = new AbortController();
      let deadline: ReturnType<typeof setTimeout> | undefined;
      const cancel = () => {
        if (controller.signal.aborted) return;
        controller.abort();
        deadline = setTimeout(() => process.exit(130), workerRestorationGraceMs);
        deadline.unref();
      };
      process.on("SIGINT", cancel);
      process.on("SIGTERM", cancel);
      try {
        const result = await runScanCommand(target, options, controller.signal);
        logger.success(`${result.status === "COMPLETED" ? "Scan complete" : "Partial scan retained"}. Report written to ${result.reportPath}`);
      } finally {
        if (deadline) clearTimeout(deadline);
        process.removeListener("SIGINT", cancel);
        process.removeListener("SIGTERM", cancel);
      }
    });
}

export async function runScanCommand(target: string, options: ScanCommandOptions, abortSignal?: AbortSignal): Promise<ScanResult> {
  const config = await loadConfigOrDefault(options.config ?? "./routecairn.config.json");
  const legacyMode = options.mode ? parseMode(options.mode) : undefined;
  const profile = options.profile ? parseProfile(options.profile) : undefined;
  const translated = resolveRequestedProfile(profile, legacyMode ?? config.defaultMode ?? defaultConfig.defaultMode, Boolean(options.profile));
  const scopeFile = options.scope;

  if (!scopeFile) {
    throw new AppError("A scope file is required. Use --scope ./examples/scope.example.json", "SCOPE_REQUIRED");
  }

  const scope = await loadScope(resolve(scopeFile));
  const finalScope = scope;
  const finalConfig = config;

  const engine = new RouteCairnEngine();
  const outputDir = resolveOutputDir(options.output, config.reportsDir, target, profile);
  const authProfile = options.auth ? await loadAuthProfile(resolve(options.auth)) : undefined;
  const targetAuthorization = options.targetAuthorization ? targetAuthorizationSchema.parse(JSON.parse(await readFile(resolve(options.targetAuthorization), "utf8"))) : undefined;
  if (options.authenticationLifecycle && options.authenticationLifecycleAuto) throw new AppError("Use either --authentication-lifecycle or --authentication-lifecycle-auto, not both.", "AUTH_LIFECYCLE_INPUT_CONFLICT");
  if (options.authenticationLifecycleAuto && !authProfile) throw new AppError("Browser-learned lifecycle automation requires --auth with an authenticated browser bootstrap.", "AUTH_LIFECYCLE_AUTOMATION_AUTH_REQUIRED");

  if ((options.authA && !options.authB) || (!options.authA && options.authB)) {
    throw new AppError("Role comparison requires both --auth-a and --auth-b.", "AUTH_PROFILE_SET_REQUIRED");
  }

  const authProfileSet = options.authA && options.authB ? await loadAuthProfileSet(resolve(options.authA), resolve(options.authB)) : undefined;
  const importedInventory = options.inventoryImport
    ? await resolveSafeInventoryImport(await loadSafeInventoryImport(resolve(options.inventoryImport)), target, {
        scope: finalScope,
        ...(authProfile ? { authProfile } : {}),
        ...(authProfileSet ? { authProfileSet } : {}),
        ...(targetAuthorization ? { targetAuthorization } : {}),
        ...(abortSignal ? { abortSignal } : {}),
        userAgent: finalScope.userAgent
      })
    : undefined;
  const executionTargetAuthorization = reserveInventoryAcquisitionBudget(targetAuthorization, importedInventory);
  if (importedInventory?.objectPairTesting && options.objectPairs) throw new AppError("Use either --inventory-import discovered object pairs or --object-pairs, not both.", "INVENTORY_IMPORT_INPUT_CONFLICT");
  const objectPairTesting = options.objectPairs || importedInventory?.objectPairTesting
    ? planObjectPairTesting(options.objectPairs ? await loadObjectPairInput(resolve(options.objectPairs)) : importedInventory!.objectPairTesting!, { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const fieldExposureTesting = options.fieldExposure
    ? planFieldExposureTesting(await loadFieldExposureInput(resolve(options.fieldExposure)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const authorizationMatrixTesting = options.authorizationMatrix
    ? planAuthorizationMatrixTesting(await loadAuthorizationMatrixInput(resolve(options.authorizationMatrix)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  if (importedInventory?.collectionAuthorization && options.collectionAuthorization) throw new AppError("Use either --inventory-import collection inventory or --collection-authorization, not both.", "INVENTORY_IMPORT_INPUT_CONFLICT");
  if (importedInventory?.fileAuthorization && options.fileAuthorization) throw new AppError("Use either --inventory-import file inventory or --file-authorization, not both.", "INVENTORY_IMPORT_INPUT_CONFLICT");
  if (importedInventory?.supabaseAuthorization && options.supabaseAuthorization) throw new AppError("Use either --inventory-import Supabase inventory or --supabase-authorization, not both.", "INVENTORY_IMPORT_INPUT_CONFLICT");
  if (importedInventory?.apiGraphql && options.apiGraphql) throw new AppError("Use either --inventory-import API inventory or --api-graphql, not both.", "INVENTORY_IMPORT_INPUT_CONFLICT");
  const collectionAuthorizationTesting = options.collectionAuthorization || importedInventory?.collectionAuthorization
    ? planCollectionAuthorizationTesting(options.collectionAuthorization ? await loadCollectionAuthorizationInput(resolve(options.collectionAuthorization)) : importedInventory!.collectionAuthorization!, { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const bulkAuthorizationTesting = options.bulkAuthorization
    ? planBulkAuthorizationTesting(await loadBulkAuthorizationInput(resolve(options.bulkAuthorization)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const fileAuthorizationTesting = options.fileAuthorization || importedInventory?.fileAuthorization
    ? planFileAuthorizationTesting(options.fileAuthorization ? await loadFileAuthorizationInput(resolve(options.fileAuthorization)) : importedInventory!.fileAuthorization!, { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const equivalentRouteTesting = options.equivalentRoutes
    ? planEquivalentRouteTesting(await loadEquivalentRouteInput(resolve(options.equivalentRoutes)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const supabaseAuthorization = options.supabaseAuthorization || importedInventory?.supabaseAuthorization
    ? planSupabaseAuthorization(options.supabaseAuthorization ? await loadSupabaseAuthorizationInput(resolve(options.supabaseAuthorization)) : importedInventory!.supabaseAuthorization!, { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const authenticationLifecycle = options.authenticationLifecycle
    ? planAuthenticationLifecycle(await loadAuthenticationLifecycleInput(resolve(options.authenticationLifecycle)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : options.authenticationLifecycleAuto
      ? planBrowserLearnedLifecycleAutomation(await loadBrowserLearnedLifecycleAutomationInput(resolve(options.authenticationLifecycleAuto)), target)
      : undefined;
  const businessInvariant = options.businessInvariants
    ? planBusinessInvariant(await loadBusinessInvariantInput(resolve(options.businessInvariants)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const controlledRace = options.controlledRaces
    ? planControlledRace(await loadControlledRaceInput(resolve(options.controlledRaces)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const apiGraphql = options.apiGraphql || importedInventory?.apiGraphql
    ? planApiGraphqlReview(options.apiGraphql ? await loadApiGraphqlInput(resolve(options.apiGraphql)) : importedInventory!.apiGraphql!, { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const protocolSecurity = options.protocolSecurity
    ? planProtocolSecurity(await loadProtocolSecurityInput(resolve(options.protocolSecurity)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const linkPortalSecurity = options.linkPortalSecurity
    ? planLinkPortalSecurity(await loadLinkPortalSecurityInput(resolve(options.linkPortalSecurity)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const operationalEndpointSecurity = options.operationalEndpoints
    ? planOperationalEndpointSecurity(await loadOperationalEndpointSecurityInput(resolve(options.operationalEndpoints)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const billingEntitlement = options.billingEntitlement
    ? planBillingEntitlement(await loadBillingEntitlementInput(resolve(options.billingEntitlement)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const activeVulnerability = options.activeVulnerability
    ? planActiveVulnerabilityValidation(await loadActiveVulnerabilityInput(resolve(options.activeVulnerability)), { target, scope: finalScope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}), ...(executionTargetAuthorization ? { targetAuthorization: executionTargetAuthorization } : {}) })
    : undefined;
  const privilegeMutationTesting = options.privilegeMutation
    ? planPrivilegeMutationTesting(privilegeMutationInputSchema.parse(JSON.parse(await readFile(resolve(options.privilegeMutation), "utf8"))), { target, maxCases: 10 })
    : undefined;
  const mutationContractSource = options.mutationContracts ? JSON.parse(await readFile(resolve(options.mutationContracts), "utf8")) : undefined;
  const parsedMutationContracts = mutationContractSource ? (Array.isArray(mutationContractSource) ? mutationContractSource : [mutationContractSource]).map((value) => controlledMutationContractSchema.parse(value)) : undefined;
  const planner = new ScanPlanner(createDefaultPluginRegistry());
  let includeModules =
    objectPairTesting || fieldExposureTesting || authorizationMatrixTesting || collectionAuthorizationTesting || bulkAuthorizationTesting || fileAuthorizationTesting || equivalentRouteTesting || privilegeMutationTesting || supabaseAuthorization || authenticationLifecycle || businessInvariant || controlledRace || apiGraphql || protocolSecurity || linkPortalSecurity || operationalEndpointSecurity || billingEntitlement || activeVulnerability || options.secretBoundary || options.includeModules?.length
      ? [
          ...new Set([
            ...(options.replaceProfileModules ? [] : (translated.includeModules ?? [])),
            ...(options.includeModules ?? []),
            ...(objectPairTesting ? (["object-pair-testing"] as ModuleId[]) : []),
            ...(fieldExposureTesting ? (["field-exposure-testing"] as ModuleId[]) : []),
            ...(authorizationMatrixTesting ? (["authorization-matrix-testing"] as ModuleId[]) : []),
            ...(collectionAuthorizationTesting ? (["collection-authorization-testing"] as ModuleId[]) : []),
            ...(bulkAuthorizationTesting ? (["bulk-authorization-testing"] as ModuleId[]) : []),
            ...(fileAuthorizationTesting ? (["file-authorization-testing"] as ModuleId[]) : []),
            ...(equivalentRouteTesting ? (["equivalent-route-testing"] as ModuleId[]) : []),
            ...(privilegeMutationTesting ? (["privilege-mutation-testing"] as ModuleId[]) : []),
            ...(supabaseAuthorization ? (["supabase-authorization"] as ModuleId[]) : []),
            ...(authenticationLifecycle ? (["authentication-lifecycle"] as ModuleId[]) : []),
            ...(businessInvariant ? (["business-invariant"] as ModuleId[]) : []),
            ...(controlledRace ? (["controlled-race"] as ModuleId[]) : []),
            ...(apiGraphql ? (["api-graphql-authorization"] as ModuleId[]) : []),
            ...(protocolSecurity ? (["protocol-security"] as ModuleId[]) : []),
            ...(linkPortalSecurity ? (["link-portal-export-security"] as ModuleId[]) : []),
            ...(operationalEndpointSecurity ? (["operational-endpoint-security"] as ModuleId[]) : []),
            ...(billingEntitlement ? (["billing-entitlement-security"] as ModuleId[]) : []),
            ...(activeVulnerability ? (["active-vulnerability-validation", "api-mapper", "parameter-analysis"] as ModuleId[]) : []),
            ...(options.secretBoundary ? (["baseline", "js-intelligence", "exposure-review", "secret-boundary"] as ModuleId[]) : []),
            ...(options.authenticationLifecycleAuto ? (["baseline", "browser-crawler"] as ModuleId[]) : [])
          ])
        ]
      : translated.includeModules;
  const assistedReview = options.assistedReview ? planAssistedReview(await loadAssistedReviewInput(resolve(options.assistedReview))) : undefined;
  if (assistedReview) includeModules = [...new Set([...(includeModules ?? resolveScanProfile(translated.profileName).enabledModules), "assisted-review" as ModuleId])];
  const plan = planner.resolve({
    ...(options.preHandover ? { preHandover: planPreHandover(JSON.parse(await readFile(resolve(options.preHandover), "utf8"))) } : {}),
    ...(executionTargetAuthorization ? { targetAuthorization: executionTargetAuthorization } : {}),
    ...(assistedReview ? { assistedReview } : {}),
    requestedProfile: translated.profileName,
    scope: finalScope,
    config: finalConfig,
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {}),
    overrides: {
      ...(options.rate ? { rateLimitPerSecond: parsePositiveNumber(options.rate, "--rate") } : {}),
      ...(options.concurrency ? { concurrency: parsePositiveInteger(options.concurrency, "--concurrency") } : {}),
      ...(options.maxRequests ? { maxRequests: parsePositiveInteger(options.maxRequests, "--max-requests") } : {}),
      ...(options.cleanupReservedRequests !== undefined ? { cleanupReservedRequests: parseNonNegativeInteger(options.cleanupReservedRequests, "--cleanup-reserved-requests") } : {}),
      ...(includeModules ? { includeModules } : {}),
      ...(!options.replaceProfileModules && translated.excludeModules ? { excludeModules: translated.excludeModules } : {}),
      ...((translated.moduleSettings || finalConfig.nextJsReview) ? { moduleSettings: {
        ...(translated.moduleSettings ?? {}),
        ...(finalConfig.nextJsReview ? { "nextjs-review": { ...(translated.moduleSettings?.["nextjs-review"] ?? {}), ...Object.fromEntries(Object.entries(finalConfig.nextJsReview).filter(([, value]) => value !== undefined)) } as ModuleSettings } : {})
      } } : {})
    },
    ...(objectPairTesting ? { objectPairTesting } : {}),
    ...(fieldExposureTesting ? { fieldExposureTesting } : {}),
    ...(authorizationMatrixTesting ? { authorizationMatrixTesting } : {}),
    ...(collectionAuthorizationTesting ? { collectionAuthorizationTesting } : {}),
    ...(bulkAuthorizationTesting ? { bulkAuthorizationTesting } : {}),
    ...(fileAuthorizationTesting ? { fileAuthorizationTesting } : {}),
    ...(equivalentRouteTesting ? { equivalentRouteTesting } : {}),
    ...(privilegeMutationTesting ? { privilegeMutationTesting } : {}),
    ...(supabaseAuthorization ? { supabaseAuthorization } : {}),
    ...(authenticationLifecycle ? { authenticationLifecycle } : {}),
    ...(businessInvariant ? { businessInvariant } : {}),
    ...(controlledRace ? { controlledRace } : {}),
    ...(apiGraphql ? { apiGraphql } : {}),
    ...(protocolSecurity ? { protocolSecurity } : {}),
    ...(linkPortalSecurity ? { linkPortalSecurity } : {}),
    ...(operationalEndpointSecurity ? { operationalEndpointSecurity } : {}),
    ...(billingEntitlement ? { billingEntitlement } : {}),
    ...(activeVulnerability ? { activeVulnerability } : {}),
    ...(translated.legacyMode ? { legacyMode: translated.legacyMode } : {}),
    ...(translated.legacyModeTranslation ? { legacyModeTranslation: translated.legacyModeTranslation } : {})
  });

  const result = await engine.scan({
    ...(abortSignal ? { abortSignal } : {}),
    target,
    scope: finalScope,
    config: finalConfig,
    plan,
    outputDir,
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {}),
    ...(parsedMutationContracts ? { controlledMutationContracts: parsedMutationContracts } : {})
  });

  const report = await loadReport(result.reportPath);
  if (result.status !== "COMPLETED" && !options.suppressProcessExitCode) process.exitCode = result.status === "CANCELLED" ? 130 : 1;
  await recordScan(
    scanIndexPath(options.historyDirectory ?? config.reportsDir),
    entryFromReport(report, {
      outputDir: dirname(result.reportPath),
      reportPath: result.reportPath,
      markdownReportPath: result.markdownReportPath,
      htmlReportPath: result.htmlReportPath
    })
  );

  return result;
}

function resolveOutputDir(output: string | undefined, reportsDir: string, target: string, profile: ScanProfile | undefined): string {
  if (output) return resolve(output);
  if (profile?.name === "monitor") return timestampedOutputDir(reportsDir, target, profile.name);
  return resolve(reportsDir);
}

function parseProfile(value: string): ScanProfile {
  try {
    return resolveScanProfile(value);
  } catch {
    throw new AppError(`Unsupported scan profile "${value}". Supported profiles: ${profileNames().join(", ")}.`, "SCAN_PROFILE_INVALID");
  }
}

async function loadConfigOrDefault(filePath: string) {
  try {
    return await loadRouteCairnConfig(resolve(filePath));
  } catch (error) {
    if (isMissingFileError(error)) {
      return routeCairnConfigSchema.parse(defaultConfig);
    }

    throw error;
  }
}

function parseMode(value: string): ScanMode {
  const parsed = scanModeSchema.safeParse(value);

  if (!parsed.success) {
    throw new AppError(`Unsupported scan mode "${value}".`, "SCAN_MODE_INVALID");
  }

  return parsed.data;
}

function resolveRequestedProfile(
  profile: ScanProfile | undefined,
  mode: ScanMode,
  explicitProfile: boolean
): {
  profileName: ScanProfileName;
  legacyMode?: ScanMode;
  legacyModeTranslation?: string;
  includeModules?: ModuleId[];
  excludeModules?: ModuleId[];
  moduleSettings?: Partial<Record<ModuleId, ModuleSettings>>;
} {
  if (explicitProfile && profile) {
    return { profileName: profile.name };
  }

  const compatibility = legacyModeCompatibility(mode);
  return {
    profileName: compatibility.profileName,
    legacyMode: mode,
    legacyModeTranslation: `Legacy mode "${mode}" translated to scan profile "${compatibility.profileName}" with a compatibility module subset at the CLI boundary.`,
    ...(compatibility.includeModules ? { includeModules: compatibility.includeModules } : {}),
    ...(compatibility.excludeModules ? { excludeModules: compatibility.excludeModules } : {}),
    ...(compatibility.moduleSettings ? { moduleSettings: compatibility.moduleSettings } : {})
  };
}

export function legacyModeCompatibility(mode: ScanMode): {
  profileName: ScanProfileName;
  includeModules?: ModuleId[];
  excludeModules?: ModuleId[];
  moduleSettings?: Partial<Record<ModuleId, ModuleSettings>>;
} {
  const base: ModuleId[] = ["baseline", "tech-fingerprint"];
  switch (mode) {
    case "quick":
      return { profileName: "quick" };
    case "api":
      return {
        profileName: "full",
        includeModules: [...base, "path-discovery", "api-mapper", "api-probe", "auth-surface", "parameter-analysis", "vulnerability-workflows"],
        moduleSettings: { "path-discovery": { pathSources: ["wordlist:api"] } }
      };
    case "admin":
      return {
        profileName: "full",
        includeModules: [...base, "path-discovery", "api-mapper", "auth-surface", "parameter-analysis", "vulnerability-workflows"],
        moduleSettings: { "path-discovery": { pathSources: ["wordlist:admin"] } }
      };
    case "backup":
      return { profileName: "full", includeModules: [...base, "path-discovery", "exposure-review"], moduleSettings: { "path-discovery": { pathSources: ["wordlist:common"] } } };
    case "headers":
      return { profileName: "full", includeModules: [...base, "header-review"] };
    case "cookies":
      return { profileName: "full", includeModules: [...base, "cookie-review"] };
    case "cors":
      return { profileName: "full", includeModules: [...base, "cors-review"] };
    case "methods":
      return { profileName: "full", includeModules: [...base, "method-review"] };
    case "js":
      return { profileName: "full", includeModules: [...base, "js-intelligence", "path-discovery", "api-mapper", "api-probe"], moduleSettings: { "path-discovery": { pathSources: ["wordlist:common", "wordlist:api"] } } };
    case "browser":
      return {
        profileName: "full",
        includeModules: [
          "baseline",
          "tech-fingerprint",
          "browser-crawler",
          "js-intelligence",
          "api-mapper",
          "api-probe",
          "auth-surface",
          "parameter-analysis",
          "nextjs-review",
          "state-aware-api",
          "vulnerability-workflows",
          "workflow-validation",
          "proof-mode"
        ]
      };
    case "full":
      return { profileName: "full" };
  }
}

function parsePositiveNumber(value: string, optionName: string): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new AppError(`${optionName} must be a positive number.`, "CLI_OPTION_INVALID");
  }

  return parsed;
}

function parsePositiveInteger(value: string, optionName: string): number {
  const parsed = parsePositiveNumber(value, optionName);

  if (!Number.isInteger(parsed)) {
    throw new AppError(`${optionName} must be a positive integer.`, "CLI_OPTION_INVALID");
  }

  return parsed;
}

function parseNonNegativeInteger(value: string, optionName: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new AppError(`${optionName} must be a non-negative integer.`, "CLI_OPTION_INVALID");
  }
  return parsed;
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
