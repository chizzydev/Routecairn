import { z } from "zod";

const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/);

export const benchmarkSelectorSchema = z.object({
  workflowId: identifier.optional(),
  caseId: identifier.optional(),
  sourceModule: z.string().min(1).max(160).optional(),
  findingType: z.string().min(1).max(160).optional()
}).strict().refine((value) => Object.values(value).some(Boolean), "A selector must constrain at least one field.");

export const benchmarkTruthCaseSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(240),
  expected: z.enum(["FINDING", "NO_FINDING"]),
  selectors: z.array(benchmarkSelectorSchema).min(1).max(20),
  category: z.string().min(1).max(120).optional(),
  tags: z.array(z.string().min(1).max(80)).max(30).default([]),
  required: z.boolean().default(true)
}).strict();

export const benchmarkThresholdsSchema = z.object({
  minRecall: z.number().min(0).max(1).default(0),
  maxFalsePositiveRate: z.number().min(0).max(1).default(1),
  maxInconclusiveRate: z.number().min(0).max(1).default(1),
  minCoverageCompleteness: z.number().min(0).max(1).default(0),
  minRepetitions: z.number().int().min(1).max(20).default(1),
  minCasesPerCategory: z.number().int().min(1).max(5000).default(1),
  requireBalancedCategories: z.boolean().default(false),
  minCleanupObservationsPerRun: z.number().int().min(0).max(5000).default(0),
  maxCleanupFailures: z.number().int().min(0).max(5000).default(0),
  maxMedianRuntimeMs: z.number().nonnegative().optional(),
  maxP95RuntimeMs: z.number().nonnegative().optional(),
  maxPeakRssBytes: z.number().int().nonnegative().optional(),
  maxRequestsPerAssessedCase: z.number().nonnegative().optional()
}).strict().default({});

export const benchmarkRegressionPolicySchema = z.object({
  maxRecallDrop: z.number().min(0).max(1).default(0),
  maxFalsePositiveRateIncrease: z.number().min(0).max(1).default(0),
  maxInconclusiveRateIncrease: z.number().min(0).max(1).default(0),
  maxCoverageDrop: z.number().min(0).max(1).default(0),
  maxRuntimeIncreaseRatio: z.number().nonnegative().default(0.25),
  maxMemoryIncreaseRatio: z.number().nonnegative().default(0.25),
  maxRequestIncreaseRatio: z.number().nonnegative().default(0.25),
  failOnCaseRegression: z.boolean().default(true)
}).strict().default({});

export const benchmarkManifestSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  id: identifier,
  label: z.string().min(1).max(240),
  description: z.string().max(2000).optional(),
  cases: z.array(benchmarkTruthCaseSchema).min(1).max(5000),
  thresholds: benchmarkThresholdsSchema,
  regression: benchmarkRegressionPolicySchema,
  metadata: z.record(z.union([z.string().max(1000), z.number().finite(), z.boolean(), z.null()])).default({})
}).strict().superRefine((value, context) => {
  const seen = new Set<string>();
  for (const item of value.cases) {
    if (seen.has(item.id)) context.addIssue({ code: z.ZodIssueCode.custom, path: ["cases"], message: `Duplicate benchmark case id: ${item.id}` });
    seen.add(item.id);
  }
});

export const benchmarkTelemetrySchema = z.object({
  runtimeMs: z.number().nonnegative(),
  peakRssBytes: z.number().int().nonnegative(),
  requestCount: z.number().int().nonnegative(),
  transmittedRequestCount: z.number().int().nonnegative().optional(),
  cpuUserMicros: z.number().int().nonnegative().optional(),
  cpuSystemMicros: z.number().int().nonnegative().optional()
}).strict();

export type BenchmarkManifest = z.infer<typeof benchmarkManifestSchema>;
export type BenchmarkTruthCase = z.infer<typeof benchmarkTruthCaseSchema>;
export type BenchmarkSelector = z.infer<typeof benchmarkSelectorSchema>;
export type BenchmarkTelemetry = z.infer<typeof benchmarkTelemetrySchema>;
export type BenchmarkClassification = "TRUE_POSITIVE" | "FALSE_NEGATIVE" | "FALSE_POSITIVE" | "TRUE_NEGATIVE" | "INCONCLUSIVE" | "UNCOVERED";
