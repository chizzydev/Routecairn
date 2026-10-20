import { resolve, join } from "node:path";
import { existsSync } from "node:fs";
const lab = process.env.ROUTECAIRN_WORKER_LAB;
if (!lab || !existsSync(join(lab, "EVIDENCE_OWNERSHIP"))) throw Error("Explicit owned worker lab required");
export default {
  cacheDir: join(resolve(lab), "vite-cache"),
  test: { environment: "node", setupFiles: ["tests/helpers/mutation-isolation.ts"], include: ["tests/unit/worker-review-verifier.test.ts","tests/dashboard/worker-custody-boundaries-native.test.ts","tests/dashboard/workflow-recovery-api.test.ts","tests/dashboard/worker-governance.test.ts", "tests/dashboard/worker-governance-api.test.ts", "tests/dashboard/immutable-plan-execution.test.ts", "tests/dashboard/cancellation-cleanup.test.ts", "tests/dashboard/worker-entry-path.test.ts", "tests/dashboard/worker-mutation-protocol.test.ts", "tests/dashboard/worker/controlled-mutation-recovery-protocol.test.ts", "tests/unit/cleanup-execution.test.ts", "tests/offensive/cleanup-transport.test.ts", "tests/dashboard/worker-resource-retention.test.ts", "tests/unit/test-isolation-retention.test.ts", "tests/unit/owned-temporary-resource.test.ts", "tests/unit/worker-process-custody.test.ts", "tests/dashboard/worker-lifecycle-native.test.ts", "tests/dashboard/worker-lease-recovery-native.test.ts"], testTimeout: 30000, hookTimeout: 30000, fileParallelism: false, maxWorkers: 1, pool: "forks", watch: false }
};
