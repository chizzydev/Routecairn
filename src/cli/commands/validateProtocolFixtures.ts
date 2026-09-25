import type { Command } from "commander";
import { runProtocolAcceptance } from "../../validation/ProtocolAcceptance.js";

export function registerValidateProtocolFixturesCommand(program: Command): void {
  program.command("validate-protocol-fixtures")
    .description("Run dedicated WebSocket, GraphQL subscription, multipart cleanup, gRPC, TLS HTTP/2, and native HTTP/3 acceptance fixtures.")
    .option("--output <directory>", "Parent for a fresh evidence directory; existing evidence is never reused.")
    .action(async (options: { output?: string }) => {
      const summary = await runProtocolAcceptance(options.output);
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      if (summary.status !== "PASSED") process.exitCode = 2;
    });
}
