import type { DashboardDatabase } from "../db/DashboardDatabase.js";
/** Synchronous feature transactions only: no await, callback IO transport or shared
 * timeout change across event-loop turns. Ordinary dashboard operations keep their policy. */
export function withTrustedDiscoveryDatabaseDeadline<T>(database: DashboardDatabase, work: () => T): T {
  const previous = database.db.pragma("busy_timeout", { simple: true }) as number;
  database.db.pragma(`busy_timeout = ${Math.min(previous, 100)}`);
  try {
    return work();
  } finally {
    database.db.pragma(`busy_timeout = ${previous}`);
  }
}
