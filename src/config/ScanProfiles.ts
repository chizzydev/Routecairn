import { z } from "zod";
import type { ScanMode } from "./ConfigSchema.js";
import { scanProfileDefinitions } from "../core/planning/ProfileDefinitions.js";
import type { ResolvedScanPlan, ScanProfileDefinition } from "../core/planning/ScanPlan.js";

export const scanProfileNameSchema = z.enum(["quick", "full", "authenticated", "monitor", "proof", "pre-handover"]);

export type ScanProfileName = z.infer<typeof scanProfileNameSchema>;
export type BrowserProfileUse = "off" | "optional" | "on";
export type AuthComparisonDepth = "none" | "single-profile" | "account-pair";
export type ScanProfile = ScanProfileDefinition;

export interface ScanProfileSummary {
  name: ScanProfileName;
  displayName: string;
  description: string;
  mode: ScanMode;
  modules: string[];
  limits: Record<string, unknown>;
  browserUse: BrowserProfileUse;
  authComparisonDepth: AuthComparisonDepth;
  proofMode: boolean;
  reportFocus: string[];
}

export const scanProfiles = scanProfileDefinitions;

export function resolveScanProfile(value: string): ScanProfile {
  const parsed = scanProfileNameSchema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`Unsupported scan profile "${value}".`);
  }
  return scanProfiles[parsed.data];
}

export function profileSummary(profile: ScanProfile | ResolvedScanPlan): ScanProfileSummary {
  if ("schemaVersion" in profile) {
    return {
      name: profile.profile,
      displayName: profile.displayName,
      description: profile.description,
      mode: legacyModeForProfile(profile.profile),
      modules: profile.modules.map((modulePlan) => modulePlan.id),
      limits: { ...profile.limits },
      browserUse: browserUseForPlan(profile),
      authComparisonDepth: authComparisonDepthForPlan(profile),
      proofMode: profile.evidence.retainProofBlocks,
      reportFocus: [...profile.reportFocus]
    };
  }

  return {
    name: profile.name,
    displayName: profile.displayName,
    description: profile.description,
    mode: legacyModeForProfile(profile.name),
    modules: [...profile.enabledModules],
    limits: { ...profile.limits },
    browserUse: profile.enabledModules.includes("browser-crawler") ? "on" : "off",
    authComparisonDepth: profile.authentication.level,
    proofMode: profile.evidence.retainProofBlocks,
    reportFocus: [...profile.reportFocus]
  };
}

export function profileNames(): ScanProfileName[] {
  return Object.keys(scanProfiles) as ScanProfileName[];
}

export function legacyModeForProfile(profile: ScanProfileName): ScanMode {
  return profile === "quick" || profile === "monitor" ? "quick" : "full";
}

function browserUseForPlan(plan: ResolvedScanPlan): BrowserProfileUse {
  return plan.modules.some((modulePlan) => modulePlan.id === "browser-crawler") ? "on" : "off";
}

function authComparisonDepthForPlan(plan: ResolvedScanPlan): AuthComparisonDepth {
  if (plan.modules.some((modulePlan) => modulePlan.id === "role-comparison")) {
    return "account-pair";
  }

  if (plan.modules.some((modulePlan) => modulePlan.id === "authenticated-testing" || modulePlan.id === "state-aware-api")) {
    return "single-profile";
  }

  return "none";
}
