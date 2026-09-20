#!/usr/bin/env node
import { Command } from "commander";
import { registerDiffCommand } from "./commands/diff.js";
import { registerDashboardCommand } from "./commands/dashboard.js";
import { registerHistoryCommand } from "./commands/history.js";
import { registerInitCommand } from "./commands/init.js";
import { registerScanCommand } from "./commands/scan.js";
import { registerSearchCommand } from "./commands/search.js";
import { registerShowCommand } from "./commands/show.js";
import { registerTriageCommand } from "./commands/triage.js";
import { registerOffensiveCommand } from "./commands/offensive.js";
import { registerValidateLocalCommand } from "./commands/validateLocal.js";
import { registerBenchmarkCommand } from "./commands/benchmark.js";
import { registerAgentCommand } from "./commands/agent.js";
import { AppError } from "../core/errors/AppError.js";
import { createLogger } from "../core/logging/Logger.js";

const logger = createLogger();

export function createCli(): Command {
  const program = new Command();

  program
    .name("routecairn")
    .description("Web attack surface intelligence for serious security testing.")
    .version("0.1.0");

  registerInitCommand(program);
  registerScanCommand(program);
  registerDashboardCommand(program);
  registerShowCommand(program);
  registerDiffCommand(program);
  registerHistoryCommand(program);
  registerSearchCommand(program);
  registerTriageCommand(program);
  registerOffensiveCommand(program);
  registerValidateLocalCommand(program);
  registerBenchmarkCommand(program);
  registerAgentCommand(program);

  return program;
}

async function main(): Promise<void> {
  const program = createCli();
  await program.parseAsync(process.argv);
}

main().catch((error: unknown) => {
  if (error instanceof AppError) {
    logger.error(error.message);
    process.exitCode = error.exitCode;
    return;
  }

  const message = error instanceof Error ? error.message : "Unknown error";
  logger.error(message);
  process.exitCode = 1;
});
