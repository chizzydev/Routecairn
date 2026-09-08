import { Command } from "commander";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { DashboardDatabase } from "../../dashboard/db/DashboardDatabase.js";
import { ServerSessionManager } from "../../dashboard/auth/ServerSession.js";
import { CredentialVault, parseVaultKey } from "../../dashboard/credentials/CredentialVault.js";
import { resolveDashboardPaths } from "../../dashboard/services/DashboardPaths.js";
import { startDashboardServer } from "../../dashboard/server/DashboardServer.js";
import { createLogger } from "../../core/logging/Logger.js";
import { DemoSeedService } from "../../dashboard/demo/DemoSeedService.js";
import { RetestTemplateVault } from "../../dashboard/retests/RetestTemplateVault.js";
import { rotateLiveAcceptancePlanKey } from "../../dashboard/execution/LiveAcceptanceService.js";
import { rotateProviderAdapterKey } from "../../dashboard/execution/ProviderAdapterService.js";
import { rotateEvidenceExportKey } from "../../dashboard/execution/EvidenceGovernanceService.js";

const logger = createLogger();

interface DashboardCommandOptions {
  host?: string;
  port?: string;
  dataDir?: string;
  mode?: "local" | "server";
  publicOrigin?: string;
  trustProxy?: boolean;
  open?: boolean;
}

export function registerDashboardCommand(program: Command): void {
  const dashboard = program
    .command("dashboard")
    .description("Launch the local RouteCairn Dashboard.")
    .option("--host <host>", "Loopback host to bind.", "127.0.0.1")
    .option("--port <port>", "Port to bind. Uses an available port by default.")
    .option("--data-dir <dir>", "Dashboard data directory.")
    .option("--mode <mode>", "Dashboard mode: local or server.", "local")
    .option("--public-origin <origin>", "Server-mode public HTTPS origin.")
    .option("--trust-proxy", "Trust a configured reverse proxy in server mode.")
    .option("--open", "Open the local dashboard URL in the system browser.")
    .action(async (options: DashboardCommandOptions) => {
      const handle = await startDashboardServer({
        ...(options.host ? { host: options.host } : {}),
        ...(options.port ? { port: parsePort(options.port) } : {}),
        ...(options.dataDir ? { dataDir: options.dataDir } : {}),
        ...(options.mode ? { mode: parseMode(options.mode) } : {}),
        ...(options.publicOrigin ? { publicOrigin: options.publicOrigin } : {}),
        ...(typeof options.trustProxy === "boolean" ? { trustProxy: options.trustProxy } : {})
      });

      logger.success(`RouteCairn Dashboard running at ${handle.url}`);
      if (handle.bootstrapUrl) logger.info(`Open this local URL to authenticate: ${handle.bootstrapUrl}`);
      if (options.open && handle.bootstrapUrl) {
        await openBrowser(handle.bootstrapUrl);
      }

      const shutdown = async () => {
        await handle.close();
        process.exit(0);
      };
      process.once("SIGINT", () => void shutdown());
      process.once("SIGTERM", () => void shutdown());
    });

  const user = dashboard.command("user").description("Manage server-mode dashboard users.");
  user
    .command("create-owner")
    .option("--data-dir <dir>", "Dashboard server data directory.")
    .description("Create the first server-mode owner.")
    .action(async (options: { dataDir: string }) => {
      const { login, password } = await promptCredentials();
      const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
      try {
        const manager = serverManager(database);
        const userId = await manager.createFirstOwner(login, password);
        logger.success(`Created first owner ${userId}.`);
      } finally {
        database.close();
      }
    });

  user
    .command("create")
    .option("--data-dir <dir>", "Dashboard server data directory.")
    .requiredOption("--role <role>", "OWNER, ANALYST, or VIEWER.")
    .description("Create a server-mode user.")
    .action(async (options: { dataDir: string; role: string }) => {
      const role = parseRole(options.role);
      const { login, password } = await promptCredentials();
      const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
      try {
        const userId = await serverManager(database).createUser({ login, password, role });
        logger.success(`Created user ${userId}.`);
      } finally {
        database.close();
      }
    });

  user.command("list").option("--data-dir <dir>").description("List server-mode users.").action((options: { dataDir?: string }) => {
    const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
    try {
      for (const item of serverManager(database).listUsers()) {
        logger.info(`${item.id} ${item.login} ${item.role} enabled=${item.enabled} activeSessions=${item.activeSessionCount}`);
      }
    } finally {
      database.close();
    }
  });

  user.command("disable").option("--data-dir <dir>").requiredOption("--user-id <id>").description("Disable a server-mode user.").action((options: { dataDir?: string; userId: string }) => {
    const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
    try {
      serverManager(database).setEnabled(options.userId, false);
      logger.success("User disabled and sessions revoked.");
    } finally {
      database.close();
    }
  });

  user.command("enable").option("--data-dir <dir>").requiredOption("--user-id <id>").description("Enable a server-mode user.").action((options: { dataDir?: string; userId: string }) => {
    const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
    try {
      serverManager(database).setEnabled(options.userId, true);
      logger.success("User enabled.");
    } finally {
      database.close();
    }
  });

  user.command("reset-password").option("--data-dir <dir>").requiredOption("--user-id <id>").description("Reset a server-mode password.").action(async (options: { dataDir?: string; userId: string }) => {
    const password = await promptPassword();
    const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
    try {
      await serverManager(database).resetPassword(options.userId, password);
      logger.success("Password reset and sessions revoked.");
    } finally {
      database.close();
    }
  });

  user.command("revoke-sessions").option("--data-dir <dir>").requiredOption("--user-id <id>").description("Revoke server-mode sessions.").action((options: { dataDir?: string; userId: string }) => {
    const database = openDashboardDatabase(requiredDataDir(options.dataDir, dashboard.opts<DashboardCommandOptions>().dataDir));
    try {
      serverManager(database).revokeUserSessions(options.userId);
      logger.success("Sessions revoked.");
    } finally {
      database.close();
    }
  });

  const vault = dashboard.command("vault").description("Manage the encrypted dashboard credential vault.");
  vault
    .command("status")
    .option("--data-dir <dir>", "Dashboard data directory.")
    .description("Show safe credential-vault availability metadata.")
    .action((options: { dataDir: string }) => {
      const dataDir = requiredDataDir(options.dataDir, dashboard.opts<{ dataDir?: string }>().dataDir);
      const database = openDashboardDatabase(dataDir);
      try {
        const service = new CredentialVault(database, parseVaultKey(process.env.ROUTECAIRN_MASTER_KEY, process.env.ROUTECAIRN_MASTER_KEY_VERSION ?? "1"));
        const status = service.status();
        logger.info(`Vault enabled=${status.enabled} algorithm=${status.algorithm}${status.keyVersion ? ` keyVersion=${status.keyVersion}` : ""}${status.reason ? ` reason=${status.reason}` : ""}`);
      } finally {
        database.close();
      }
    });

  vault
    .command("rotate-key")
    .option("--data-dir <dir>", "Dashboard data directory.")
    .description("Offline rotation for encrypted credential profiles. Uses ROUTECAIRN_MASTER_KEY and ROUTECAIRN_NEW_MASTER_KEY.")
    .action((options: { dataDir: string }) => {
      const dataDir = requiredDataDir(options.dataDir, dashboard.opts<{ dataDir?: string }>().dataDir);
      const current = parseVaultKey(process.env.ROUTECAIRN_MASTER_KEY, process.env.ROUTECAIRN_MASTER_KEY_VERSION ?? "1");
      const next = parseVaultKey(process.env.ROUTECAIRN_NEW_MASTER_KEY, process.env.ROUTECAIRN_NEW_MASTER_KEY_VERSION);
      if (!current) throw new Error("ROUTECAIRN_MASTER_KEY is required for vault key rotation.");
      if (!next) throw new Error("ROUTECAIRN_NEW_MASTER_KEY is required for vault key rotation.");
      if (current.version === next.version) throw new Error("ROUTECAIRN_NEW_MASTER_KEY_VERSION must differ from the current key version.");
      const database = openDashboardDatabase(dataDir);
      try {
        let rotatedCredentials = 0;
        let rotatedTemplates = 0;
        let rotatedAcceptancePlans = 0;
        let rotatedProviderAdapters = 0;
        let rotatedEvidenceExports = 0;
        const dashboardPaths = resolveDashboardPaths(dataDir);
        database.transaction(() => {
          rotatedCredentials = new CredentialVault(database, current).rotateKey(next);
          rotatedTemplates = new RetestTemplateVault(database.db, current).rotateKey(next);
          rotatedAcceptancePlans = rotateLiveAcceptancePlanKey(database, current, next);
          rotatedProviderAdapters = rotateProviderAdapterKey(database, current, next);
          rotatedEvidenceExports = rotateEvidenceExportKey(database, dashboardPaths, current, next);
        });
        logger.success(`Rotated ${rotatedCredentials} credential profile(s), ${rotatedTemplates} retest template(s), ${rotatedAcceptancePlans} live acceptance plan(s), ${rotatedProviderAdapters} provider-adapter version(s), and ${rotatedEvidenceExports} encrypted evidence export(s) to key version ${next.version}. Back up the database and new key material together.`);
      } finally {
        database.close();
      }
    });

  dashboard.command("demo-seed")
    .option("--data-dir <dir>", "Development dashboard data directory.")
    .description("Seed fictional development-only Command Center data.")
    .action(async (options: { dataDir?: string }) => {
      if (process.env.NODE_ENV === "production") throw new Error("Demo seeding is disabled in production mode.");
      const dataDir = requiredDataDir(options.dataDir, dashboard.opts<{ dataDir?: string }>().dataDir);
      const database = openDashboardDatabase(dataDir);
      try {
        const manager = serverManager(database);
        let users = manager.listUsers();
        if (users.length === 0) {
          await manager.createFirstOwner("demo-owner@routecairn.test", "RouteCairn-Demo-Owner-Only-2026!");
          await manager.createUser({ login: "demo-analyst@routecairn.test", password: "RouteCairn-Demo-Analyst-2026!", role: "ANALYST" });
          await manager.createUser({ login: "demo-viewer@routecairn.test", password: "RouteCairn-Demo-Viewer-2026!", role: "VIEWER" });
          users = manager.listUsers();
        }
        const owner = users.find((user) => user.role === "OWNER");
        const analyst = users.find((user) => user.role === "ANALYST");
        const result = new DemoSeedService(database, resolveDashboardPaths(dataDir)).seed({ ...(owner ? { ownerUserId: owner.id } : {}), ...(analyst ? { analystUserId: analyst.id } : {}), ...(process.env.NODE_ENV ? { environment: process.env.NODE_ENV } : {}) });
        logger.success(`Seeded ${result.findingCount} fictional findings across ${result.projectIds.length} projects and ${result.targetIds.length} targets.`);
      } finally {
        database.close();
      }
    });
}

function requiredDataDir(...values: Array<string | undefined>): string {
  const value = values.find((candidate) => candidate && candidate.trim().length > 0);
  if (!value) throw new Error("--data-dir is required for this dashboard command.");
  return value;
}

function parsePort(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
    throw new Error("--port must be an integer from 0 to 65535.");
  }
  return parsed;
}

function parseMode(value: string): "local" | "server" {
  if (value !== "local" && value !== "server") throw new Error("--mode must be local or server.");
  return value;
}

async function openBrowser(url: string): Promise<void> {
  const { spawn } = await import("node:child_process");
  const command = process.platform === "win32" ? "cmd" : process.platform === "darwin" ? "open" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  const child = spawn(command, args, { detached: true, stdio: "ignore", windowsHide: true });
  child.unref();
}

function openDashboardDatabase(dataDir: string): DashboardDatabase {
  const database = new DashboardDatabase(resolveDashboardPaths(dataDir).databasePath);
  database.migrate();
  return database;
}

function serverManager(database: DashboardDatabase): ServerSessionManager {
  return new ServerSessionManager(database, {
    publicOrigin: "https://routecairn.local",
    sessionSecret: "cli-user-management-only-secret-value",
    trustProxy: false,
    developmentInsecureHttp: false
  });
}

async function promptCredentials(): Promise<{ login: string; password: string }> {
  const rl = createInterface({ input, output });
  try {
    const login = await rl.question("Username or email: ");
    const password = await promptPassword();
    return { login, password };
  } finally {
    rl.close();
  }
}

async function promptPassword(): Promise<string> {
  output.write("Password: ");
  return new Promise((resolvePrompt, rejectPrompt) => {
    let value = "";
    const onData = (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      for (const char of text) {
        if (char === "\u0003") {
          cleanup();
          rejectPrompt(new Error("Password prompt cancelled."));
          return;
        }
        if (char === "\r" || char === "\n") {
          cleanup();
          output.write("\n");
          resolvePrompt(value);
          return;
        }
        if (char === "\b" || char === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        value += char;
      }
    };
    const cleanup = () => {
      input.off("data", onData);
      if (input.isTTY) input.setRawMode(false);
      input.pause();
    };
    if (input.isTTY) input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

function parseRole(value: string) {
  const normalized = value.toUpperCase();
  if (normalized !== "OWNER" && normalized !== "ANALYST" && normalized !== "VIEWER") throw new Error("--role must be OWNER, ANALYST, or VIEWER.");
  return normalized;
}
