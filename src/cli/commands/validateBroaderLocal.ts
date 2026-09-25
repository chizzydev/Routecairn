import type { Command } from "commander";
import { runBroaderAcceptanceValidation } from "../../validation/BroaderAcceptanceValidation.js";

export function registerValidateBroaderLocalCommand(program: Command): void {
  program.command("validate-broader-local")
    .description("Run the complete eight-lane acceptance grid against an owned disposable multi-tenant loopback app. Never accepts an external target.")
    .option("--output <directory>", "Parent for a fresh evidence directory; existing evidence is never reused.")
    .action(async (options: { output?: string }) => {
      const summary = await runBroaderAcceptanceValidation(options.output);
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      if (summary.status !== "PASSED") process.exitCode = 2;
    });
}
