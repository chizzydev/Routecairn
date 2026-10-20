import { join, resolve } from "node:path";
import { lstatSync, readFileSync } from "node:fs";
const lab = process.env.ROUTECAIRN_WORKER_LAB;
if (process.platform !== "win32" || !lab) throw Error("EXPLICIT_OWNED_WINDOWS_BUSINESSFLOW_LAB_REQUIRED");
const marker = lstatSync(join(lab, "EVIDENCE_OWNERSHIP"));
if (
  !marker.isFile() ||
  marker.isSymbolicLink() ||
  marker.nlink !== 1 ||
  marker.size > 1000 ||
  !readFileSync(join(lab, "EVIDENCE_OWNERSHIP"), "utf8").trim()
)
  throw Error("OWNED_EVIDENCE_MARKER_REQUIRED");
export default {
  cacheDir: join(resolve(lab), "vite-cache"),
  test: {
    environment: "node",
    setupFiles: ["tests/helpers/mutation-isolation.ts", "tests/helpers/native-process-timing.ts"],
    include: [
      "tests/unit/businessflow-contract.test.ts",
      "tests/unit/prospective-assessment-intake.test.ts",
      "tests/dashboard/businessflow-native.test.ts",
      "tests/dashboard/businessflow-relationship-identity.test.ts",
      "tests/dashboard/businessflow-controls.test.ts",
      "tests/dashboard/businessflow-triage-history.test.ts",
      "tests/dashboard/businessflow-triage-http.test.ts",
      "tests/dashboard/businessflow-triage-comparison.test.ts",
      "apps/dashboard-ui/src/BusinessRelationshipPanel.test.tsx",
      "apps/dashboard-ui/src/ApplicationEvidenceTriage.test.tsx"
    ],
    testTimeout: 30000,
    hookTimeout: 30000,
    fileParallelism: false,
    maxWorkers: 1,
    pool: "forks",
    watch: false
  }
};
