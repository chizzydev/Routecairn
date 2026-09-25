import type { Command } from "commander";
import { runAuthenticationFixtureAcceptance } from "../../validation/AuthenticationFixtureAcceptance.js";

export function registerValidateAuthenticationFixturesCommand(program: Command): void {
  program.command("validate-authentication-fixtures")
    .description("Run provider-emulator, OIDC callback, and browser passkey acceptance against disposable loopback fixtures.")
    .option("--output <directory>", "Parent for a fresh evidence directory; existing evidence is never reused.")
    .action(async (options: { output?: string }) => {
      const summary = await runAuthenticationFixtureAcceptance(options.output);
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      if (summary.status !== "PASSED") process.exitCode = 2;
    });
}
