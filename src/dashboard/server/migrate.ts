import { DashboardDatabase } from "../db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../services/DashboardPaths.js";

const dataDirIndex = process.argv.indexOf("--data-dir");
const dataDir = dataDirIndex >= 0 ? process.argv[dataDirIndex + 1] : undefined;
const paths = resolveDashboardPaths(dataDir);
const database = new DashboardDatabase(paths.databasePath);
database.migrate();
database.close();
console.log(`RouteCairn Dashboard database migrated: ${paths.databasePath}`);
