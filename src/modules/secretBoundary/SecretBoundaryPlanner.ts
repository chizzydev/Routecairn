import { z } from "zod";
import type { ModuleSettings } from "../../core/planning/ScanPlan.js";
import type { SecretBoundaryPlan } from "./SecretBoundaryTypes.js";

export const defaultSecretBoundaryProbePaths = [
  "/config.json",
  "/runtime-config.js",
  "/env.js",
  "/asset-manifest.json",
  "/build-info.json",
  "/api/config",
  "/debug",
  "/debug/config",
  "/debug.log",
  "/error.log",
  "/server.log",
  "/graphql"
] as const;

const settingsSchema = z.object({
  maxSecretBoundaryObservedResponses: z.number().int().positive().max(1000).default(250),
  maxSecretBoundaryAdditionalRequests: z.number().int().min(0).max(32).default(12),
  maxSecretBoundarySourceMaps: z.number().int().min(0).max(16).default(4),
  maxSecretBoundaryCandidatesPerSource: z.number().int().positive().max(500).default(100),
  maxSecretBoundaryCandidates: z.number().int().positive().max(5000).default(1000),
  maxSecretBoundaryAnalysisBytes: z.number().int().positive().max(1024 * 1024).default(256 * 1024),
  inspectSecretBoundarySourceMaps: z.boolean().default(true),
  secretBoundaryProbePaths: z.array(z.string().startsWith("/").max(300)).max(32).default([...defaultSecretBoundaryProbePaths])
}).strict();

export function planSecretBoundary(settings: ModuleSettings): SecretBoundaryPlan {
  const parsed = settingsSchema.parse({
    maxSecretBoundaryObservedResponses: settings.maxSecretBoundaryObservedResponses,
    maxSecretBoundaryAdditionalRequests: settings.maxSecretBoundaryAdditionalRequests,
    maxSecretBoundarySourceMaps: settings.maxSecretBoundarySourceMaps,
    maxSecretBoundaryCandidatesPerSource: settings.maxSecretBoundaryCandidatesPerSource,
    maxSecretBoundaryCandidates: settings.maxSecretBoundaryCandidates,
    maxSecretBoundaryAnalysisBytes: settings.maxSecretBoundaryAnalysisBytes,
    inspectSecretBoundarySourceMaps: settings.inspectSecretBoundarySourceMaps,
    secretBoundaryProbePaths: settings.secretBoundaryProbePaths
  });
  const probePaths = [...new Set(parsed.secretBoundaryProbePaths.map(normalizeProbePath))];
  if (probePaths.some((path) => path === "/")) throw new Error("Secret-boundary probes may not target the application root.");
  return {
    schemaVersion: 1,
    enabled: true,
    maxObservedResponses: parsed.maxSecretBoundaryObservedResponses,
    maxAdditionalRequests: parsed.maxSecretBoundaryAdditionalRequests,
    maxSourceMaps: parsed.maxSecretBoundarySourceMaps,
    maxCandidatesPerSource: parsed.maxSecretBoundaryCandidatesPerSource,
    maxTotalCandidates: parsed.maxSecretBoundaryCandidates,
    maxAnalysisBytes: parsed.maxSecretBoundaryAnalysisBytes,
    inspectSourceMaps: parsed.inspectSecretBoundarySourceMaps,
    probePaths,
    notes: [
      "The engine is read-only and issues only bounded same-origin GET requests.",
      "Secret values are classified in transient memory and never copied into reports, findings, request audit, or comparison fingerprints.",
      "Client-safe material is classified separately from server-only credentials; publishability does not imply privilege."
    ]
  };
}

function normalizeProbePath(value: string): string {
  const parsed = new URL(value, "https://routecairn.invalid");
  if (parsed.origin !== "https://routecairn.invalid" || parsed.username || parsed.password || parsed.hash || parsed.search) throw new Error("Secret-boundary probe paths must be exact relative paths without query strings, fragments, or credentials.");
  return parsed.pathname.replace(/\/{2,}/g, "/");
}
