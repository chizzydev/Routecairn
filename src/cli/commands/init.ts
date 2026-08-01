import { Command } from "commander";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { defaultConfig, exampleScope } from "../../config/defaults.js";
import { createLogger } from "../../core/logging/Logger.js";

const logger = createLogger();

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description("Create RouteCairn starter config, examples, and reports folders.")
    .option("-f, --force", "Overwrite existing starter files.")
    .action(async (options: { force?: boolean }) => {
      await initWorkspace(process.cwd(), Boolean(options.force));
    });
}

export async function initWorkspace(rootDir: string, force: boolean): Promise<void> {
  await mkdir(join(rootDir, "examples"), { recursive: true });
  await mkdir(join(rootDir, "reports"), { recursive: true });

  await writeJsonIfNeeded(join(rootDir, "routecairn.config.json"), defaultConfig, force);
  await writeJsonIfNeeded(join(rootDir, "examples", "scope.example.json"), exampleScope, force);

  logger.success("RouteCairn workspace initialized.");
}

async function writeJsonIfNeeded(filePath: string, value: unknown, force: boolean): Promise<void> {
  const flag = force ? "w" : "wx";

  try {
    await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { flag });
    logger.info(`Created ${filePath}`);
  } catch (error) {
    if (isFileExistsError(error)) {
      logger.warn(`Skipped existing file ${filePath}`);
      return;
    }

    throw error;
  }
}

function isFileExistsError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST";
}
