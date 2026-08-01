import { Command } from "commander";
import { dirname, resolve } from "node:path";
import { routeCairnConfigSchema, scanModeSchema, type ScanMode } from "../../config/ConfigSchema.js";
import { profileNames, resolveScanProfile, type ScanProfile, type ScanProfileName } from "../../config/ScanProfiles.js";
import { defaultConfig } from "../../config/defaults.js";
import { loadRouteCairnConfig, loadScope } from "../../config/loadConfig.js";
import { RouteCairnEngine } from "../../core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../core/engine/ScanOrchestrator.js";
import { loadAuthProfile } from "../../core/auth/AuthProfile.js";
import { loadAuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { createLogger } from "../../core/logging/Logger.js";
import { ScanPlanner } from "../../core/planning/ScanPlanner.js";
import type { ModuleId, ModuleSettings } from "../../core/planning/ScanPlan.js";
import { loadFieldExposureInput, planFieldExposureTesting } from "../../modules/fieldExposureTesting/FieldExposurePlanner.js";
import { loadObjectPairInput, planObjectPairTesting } from "../../modules/objectPairTesting/ObjectPairPlanner.js";
import { loadReport } from "../../reports/ReportSummary.js";
import { entryFromReport, recordScan, scanIndexPath, timestampedOutputDir } from "../../storage/ScanIndex.js";

const logger = createLogger();

interface ScanCommandOptions {
  scope?: string;
  mode?: string;
  profile?: string;
  rate?: string;
  concurrency?: string;
  output?: string;
  config?: string;
  auth?: string;
  authA?: string;
  authB?: string;
  objectPairs?: string;
  fieldExposure?: string;
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
    .option("--output <dir>", "Directory where report.json should be written.")
    .option("--config <file>", "Path to routecairn.config.json.", "./routecairn.config.json")
    .option("--auth <file>", "Path to a RouteCairn auth profile JSON for authenticated comparison.")
    .option("--auth-a <file>", "Path to Account A auth profile JSON for role comparison.")
    .option("--auth-b <file>", "Path to Account B auth profile JSON for role comparison.")
    .option("--object-pairs <file>", "Path to an explicit object-pair testing JSON file.")
    .option("--field-exposure <file>", "Path to an explicit controlled field-exposure testing JSON file.")
    .action(async (target: string, options: ScanCommandOptions) => {
      const result = await runScanCommand(target, options);
      logger.success(`Scan complete. Report written to ${result.reportPath}`);
    });
}

export async function runScanCommand(target: string, options: ScanCommandOptions): Promise<{ reportPath: string; markdownReportPath: string; htmlReportPath: string }> {
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

  if ((options.authA && !options.authB) || (!options.authA && options.authB)) {
    throw new AppError("Role comparison requires both --auth-a and --auth-b.", "AUTH_PROFILE_SET_REQUIRED");
  }

  const authProfileSet = options.authA && options.authB ? await loadAuthProfileSet(resolve(options.authA), resolve(options.authB)) : undefined;
  const objectPairTesting = options.objectPairs
    ? planObjectPairTesting(await loadObjectPairInput(resolve(options.objectPairs)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const fieldExposureTesting = options.fieldExposure
    ? planFieldExposureTesting(await loadFieldExposureInput(resolve(options.fieldExposure)), { target, scope: finalScope, ...(authProfileSet ? { authProfileSet } : {}) })
    : undefined;
  const planner = new ScanPlanner(createDefaultPluginRegistry());
  const includeModules =
    objectPairTesting || fieldExposureTesting
      ? [
          ...new Set([
            ...(translated.includeModules ?? []),
            ...(objectPairTesting ? (["object-pair-testing"] as ModuleId[]) : []),
            ...(fieldExposureTesting ? (["field-exposure-testing"] as ModuleId[]) : [])
          ])
        ]
      : translated.includeModules;
  const plan = planner.resolve({
    requestedProfile: translated.profileName,
    scope: finalScope,
    config: finalConfig,
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {}),
    overrides: {
      ...(options.rate ? { rateLimitPerSecond: parsePositiveNumber(options.rate, "--rate") } : {}),
      ...(options.concurrency ? { concurrency: parsePositiveInteger(options.concurrency, "--concurrency") } : {}),
      ...(includeModules ? { includeModules } : {}),
      ...(translated.excludeModules ? { excludeModules: translated.excludeModules } : {}),
      ...(translated.moduleSettings ? { moduleSettings: translated.moduleSettings } : {})
    },
    ...(objectPairTesting ? { objectPairTesting } : {}),
    ...(fieldExposureTesting ? { fieldExposureTesting } : {}),
    ...(translated.legacyMode ? { legacyMode: translated.legacyMode } : {}),
    ...(translated.legacyModeTranslation ? { legacyModeTranslation: translated.legacyModeTranslation } : {})
  });

  const result = await engine.scan({
    target,
    scope: finalScope,
    config: finalConfig,
    plan,
    outputDir,
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {})
  });

  const report = await loadReport(result.reportPath);
  await recordScan(
    scanIndexPath(config.reportsDir),
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

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
