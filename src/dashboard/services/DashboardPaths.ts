import { homedir } from "node:os";
import { resolve } from "node:path";

export interface DashboardPaths {
  dataDir: string;
  databasePath: string;
  reportsDir: string;
  artifactsDir: string;
  proofPacksDir: string;
  fingerprintKeyPath: string;
  executablePlanKeyPath: string;
  mutationJournalDir: string;
  mutationJournalRegistryPath: string;
  workersDir: string;
}

export function resolveDashboardPaths(dataDir?: string): DashboardPaths {
  const root = resolve(dataDir ?? process.env.ROUTECAIRN_DASHBOARD_DIR ?? resolve(homedir(), ".routecairn", "dashboard"));
  const mutationJournalDir = resolve(process.env.ROUTECAIRN_MUTATION_DIR ?? resolve(root, "controlled-mutations"));
  return {
    dataDir: root,
    databasePath: resolve(root, "routecairn-dashboard.sqlite"),
    reportsDir: resolve(root, "reports"),
    artifactsDir: resolve(root, "artifacts"),
    proofPacksDir: resolve(root, "proof-packs"),
    fingerprintKeyPath: resolve(root, "keys", "finding-fingerprint.key"),
    executablePlanKeyPath: resolve(root, "keys", "executable-plan.key"),
    mutationJournalDir,
    mutationJournalRegistryPath: resolve(mutationJournalDir, "mutation-journals.json"),
    workersDir: resolve(root, "workers")
  };
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}
