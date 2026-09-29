import { Command } from "commander";
import { createLogger } from "../../core/logging/Logger.js";
import { loadOastServiceConfig, readOastServiceSecrets } from "../../oast/OastConfig.js";
import { OastService } from "../../oast/OastService.js";

const logger = createLogger();

export function registerOastCommand(program: Command): void {
  const command = program.command("oast").description("Run RouteCairn's tenant-isolated out-of-band callback service.");
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
        const stop = () => { if (stopping) return; stopping = true; void service.close().finally(resolve); };
        process.once("SIGINT", stop); process.once("SIGTERM", stop);
      });
    });
}
