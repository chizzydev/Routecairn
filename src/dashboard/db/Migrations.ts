import { DashboardMigrationsApplicationHypotheses } from "./DashboardMigrationsApplicationHypotheses.js";
import { DashboardMigrationsApplicationSchema } from "./DashboardMigrationsApplicationSchema.js";
import { DashboardMigrationsApplicationMapping } from "./DashboardMigrationsApplicationMapping.js";
import { DashboardMigrationsAuthorizationWorkbench } from "./DashboardMigrationsAuthorizationWorkbench.js";
import { DashboardMigrationsInitial } from "./DashboardMigrationsInitial.js";
import { DashboardMigrationsWorkflows } from "./DashboardMigrationsWorkflows.js";
import { DashboardMigrationsOperations } from "./DashboardMigrationsOperations.js";
import { DashboardMigrationsTrustedDiscovery } from "./DashboardMigrationsTrustedDiscovery.js";
import { DashboardMigrationsWorkerCustody } from "./DashboardMigrationsWorkerCustody.js";
import { DashboardMigrationsRecoveryOperations } from "./DashboardMigrationsRecoveryOperations.js";
import { DashboardMigrationsCleanupAttempts } from "./DashboardMigrationsCleanupAttempts.js";
import { DashboardMigrationsObservedState } from "./DashboardMigrationsObservedState.js";
import { DashboardMigrationsApplicationDiscovery } from "./DashboardMigrationsApplicationDiscovery.js";
import { DashboardMigrationsOwnedIntake } from "./DashboardMigrationsOwnedIntake.js";
import { DashboardMigrationsBusinessTriage } from "./DashboardMigrationsBusinessTriage.js";
export const dashboardSchemaVersion = 56;
export const dashboardMigrations: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [
  ...DashboardMigrationsInitial,
  ...DashboardMigrationsWorkflows,
  ...DashboardMigrationsOperations,
  ...DashboardMigrationsTrustedDiscovery,
  ...DashboardMigrationsWorkerCustody,
  ...DashboardMigrationsRecoveryOperations,
  ...DashboardMigrationsCleanupAttempts,
  ...DashboardMigrationsAuthorizationWorkbench,
  ...DashboardMigrationsApplicationMapping,
  ...DashboardMigrationsApplicationSchema,
  ...DashboardMigrationsApplicationHypotheses,
  ...DashboardMigrationsObservedState,
  ...DashboardMigrationsApplicationDiscovery,
  ...DashboardMigrationsBusinessTriage,
  ...DashboardMigrationsOwnedIntake
];
