import { DashboardMigrationsInitial } from './DashboardMigrationsInitial.js';
import { DashboardMigrationsWorkflows } from './DashboardMigrationsWorkflows.js';
import { DashboardMigrationsOperations } from './DashboardMigrationsOperations.js';
export const dashboardSchemaVersion = 44;
export const dashboardMigrations: readonly {
  version: number;
  sql: string;
  requiresForeignKeysDisabled?: boolean;
}[] = [...DashboardMigrationsInitial, ...DashboardMigrationsWorkflows, ...DashboardMigrationsOperations];
