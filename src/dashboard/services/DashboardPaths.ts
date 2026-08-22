import { homedir } from "node:os";
import { resolve } from "node:path";

export interface DashboardPaths {
  dataDir: string;
  databasePath: string;
  reportsDir: string;
  artifactsDir: string;
  proofPacksDir: string;
  fingerprintKeyPath: string;
  mutationJournalDir: string;
  mutationJournalRegistryPath: string;
}

export function resolveDashboardPaths(dataDir?: string): DashboardPaths {
  const root = resolve(dataDir ?? process.env.ROUTECAIRN_DASHBOARD_DIR ?? resolve(homedir(), ".routecairn", "dashboard"));
  return {
    dataDir: root,
    databasePath: resolve(root, "routecairn-dashboard.sqlite"),
    reportsDir: resolve(root, "reports"),
    artifactsDir: resolve(root, "artifacts"),
    proofPacksDir: resolve(root, "proof-packs"),
    fingerprintKeyPath: resolve(root, "keys", "finding-fingerprint.key"),
    mutationJournalDir: resolve(root, "controlled-mutations"),
    mutationJournalRegistryPath: resolve(root, "controlled-mutation-journals.json")
  };
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}
