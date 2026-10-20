import { resolve, join } from "node:path";
import { lstatSync, realpathSync, existsSync } from "node:fs";

const value = process.env.ROUTECAIRN_CA_COMPARISON_FIXTURE_PARENT;
if (!value) throw new Error("An explicitly owned fresh comparison fixture parent is required");
const parent = resolve(value);
if (lstatSync(parent).isSymbolicLink() || realpathSync.native(parent).toLowerCase() !== parent.toLowerCase() || !existsSync(join(parent, "EVIDENCE_OWNERSHIP"))) throw new Error("Invalid fixture custody");

// Load with --configLoader native. No original global deletion hooks; all Vite
// caches/results/TEMP are bound to this disposable caller-owned review run.
export default {
  cacheDir: join(parent, "vite-cache"),
  test: {
    environment: "node", setupFiles: [],
    include: ["tests/dashboard/continuous-assurance-comparison-transaction.test.ts", "tests/unit/comparison-integrity.test.ts", "tests/dashboard/continuous-assurance-service.test.ts", "tests/dashboard/continuous-assurance-interruption.test.ts"],
    testTimeout: 30000, hookTimeout: 30000, fileParallelism: false, maxWorkers: 1,
    pool: "forks", watch: false
  }
};
