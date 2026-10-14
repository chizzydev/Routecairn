import { DashboardMigrationsInitial } from './DashboardMigrationsInitial.js';
import { DashboardMigrationsWorkflows } from './DashboardMigrationsWorkflows.js';
import { DashboardMigrationsOperations } from './DashboardMigrationsOperations.js';
import { DashboardMigrationsTrustedDiscovery } from './DashboardMigrationsTrustedDiscovery.js';
export const dashboardSchemaVersion = 45;
export const dashboardMigrations: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [...DashboardMigrationsInitial, ...DashboardMigrationsWorkflows, ...DashboardMigrationsOperations, ...DashboardMigrationsTrustedDiscovery];
