import base from "./vitest.businessflow.config.mjs";
export default {
  ...base,
  test: {
    ...base.test,
    setupFiles: [
      ...base.test.setupFiles.filter((p) => p !== "tests/helpers/native-process-timing.ts"),
      "tests/helpers/assessment-stage-timing.ts"
    ],
    include: [
      ...new Set([
        ...base.test.include,
        ...[
          "tests/dashboard/owned-application-intake.test.ts",
          "tests/dashboard/deep-businessflow-native.test.ts",
          "tests/dashboard/deep-businessflow-controls.test.ts",
          "tests/dashboard/deep-businessflow-connectivity.test.ts",
          "tests/dashboard/analyst-handoff-history.test.ts",
          "tests/dashboard/owned-intake-handoff-http.test.ts",
          "tests/dashboard/owned-har-cli.test.ts",
          "tests/dashboard/owned-intake-receipt-recovery.test.ts",
          "tests/dashboard/analyst-comparison-history.test.ts",
          "tests/unit/owned-har-minimizer.test.ts",
          "tests/unit/prospective-assessment-intake.test.ts",
          "apps/dashboard-ui/src/OwnedApplicationIntake.test.tsx",
          "apps/dashboard-ui/src/AnalystHandoff.test.tsx"
        ]
      ])
    ]
  }
};
