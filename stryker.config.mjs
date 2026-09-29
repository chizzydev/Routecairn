export default {
  mutate: [
    "src/core/scope/ScopeMatcher.ts",
    "src/core/authorization/TargetAuthorization.ts",
    "src/core/offensive/MutationPolicy.ts"
  ],
  testRunner: "vitest",
  mutator: { excludedMutations: ["StringLiteral"] },
  vitest: { configFile: "vitest.mutation.config.ts" },
  coverageAnalysis: "perTest",
  reporters: ["clear-text", "progress", "html", "json"],
  htmlReporter: { fileName: "reports/mutation/index.html" },
  jsonReporter: { fileName: "reports/mutation/mutation.json" },
  thresholds: { high: 75, low: 60, break: 55 },
  tempDirName: ".stryker-tmp",
  cleanTempDir: true,
  concurrency: 2,
  timeoutMS: 30000
};
