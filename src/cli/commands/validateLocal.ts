import type { Command } from "commander";
import { runLocalTargetValidation } from "../../validation/LocalTargetValidation.js";

export function registerValidateLocalCommand(program: Command): void {
  program.command("validate-local")
    .description("Run isolated disposable loopback acceptance: real workers, browser, mutation, rollback, recovery and proof artifacts. Never accepts an external target.")
    .option("--output <directory>", "Parent for a fresh validation directory; existing data is never reused.")
    .action(async (options: { output?: string }) => { const summary = await runLocalTargetValidation(options.output); process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`); });
}
