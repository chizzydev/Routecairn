import { Command } from "commander";
import { createLogger } from "../../core/logging/Logger.js";
import { loadOastServiceConfig, readOastServiceSecrets } from "../../oast/OastConfig.js";
import { OastService } from "../../oast/OastService.js";
import { verifyOastDeployment } from "../../oast/OastDeploymentVerification.js";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const logger = createLogger();

export function registerOastCommand(program: Command): void {
  const command = program.command("oast").description("Run RouteCairn's tenant-isolated out-of-band callback service.");
  command.command("verify-deployment")
    .description("Verify an owner-authorized public DNS and HTTPS deployment and retain secret-free evidence.")
    .requiredOption("--manifest <file>", "Path to the reviewed public deployment manifest.")
    .requiredOption("--output <file>", "Fresh evidence output path; existing evidence is never overwritten.")
    .action(async (options: { manifest: string; output: string }) => {
      const report = await verifyOastDeployment(JSON.parse(await readFile(resolve(options.manifest), "utf8")));
      await writeFile(resolve(options.output), `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      if (report.status !== "COMPLETED") process.exitCode = 1;
      logger.info(`OAST deployment verification: ${report.status}; ${resolve(options.output)}`);
    });
  command.command("serve")
    .description("Start bounded DNS, HTTP, and optional HTTPS callback listeners.")
    .requiredOption("--config <file>", "Path to an OAST service configuration file.")
    .action(async (options: { config: string }) => {
      const config = await loadOastServiceConfig(options.config);
      const service = new OastService(config, readOastServiceSecrets(config));
      await service.start();
      logger.success(`OAST service listening in ${config.mode.toLowerCase().replace("_", "-")} mode for ${config.baseDomain}.`);
      await new Promise<void>((resolve) => {
        let stopping = false;
        const renew = () => { if (!stopping) void service.reloadTls().catch(() => logger.error("OAST TLS reload failed; previous certificate remains active.")); };
        const stop = () => { if (stopping) return; stopping = true; process.off("SIGHUP", renew); void service.close().finally(resolve); };
        process.on("SIGHUP", renew);
        process.once("SIGINT", stop); process.once("SIGTERM", stop);
      });
    });
}
