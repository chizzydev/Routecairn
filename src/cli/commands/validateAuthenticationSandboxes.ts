import type { Command } from "commander";
import { loadAuthenticationSandboxAcceptance, runAuthenticationSandboxAcceptance } from "../../validation/AuthenticationSandboxAcceptance.js";

export function registerValidateAuthenticationSandboxesCommand(program: Command): void {
  program.command("validate-authentication-sandboxes")
    .description("Run authorized provider, OIDC, and passkey acceptance against disposable development targets.")
    .requiredOption("--manifest <file>", "Authentication sandbox acceptance manifest.")
    .option("--output <directory>", "Parent for a fresh evidence directory; existing evidence is never reused.")
    .action(async (options: { manifest: string; output?: string }) => {
      const manifest = await loadAuthenticationSandboxAcceptance(options.manifest);
      const summary = await runAuthenticationSandboxAcceptance(manifest, options.output);
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      if (summary.status !== "PASSED") process.exitCode = 2;
    });
}
