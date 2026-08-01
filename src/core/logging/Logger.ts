import chalk from "chalk";

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  success(message: string): void;
}

export function createLogger(): Logger {
  return {
    info(message: string): void {
      console.log(chalk.cyan(message));
    },
    warn(message: string): void {
      console.warn(chalk.yellow(message));
    },
    error(message: string): void {
      console.error(chalk.red(message));
    },
    success(message: string): void {
      console.log(chalk.green(message));
    }
  };
}
