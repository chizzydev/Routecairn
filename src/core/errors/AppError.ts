export class AppError extends Error {
  public readonly code: string;
  public readonly exitCode: number;

  public constructor(message: string, code = "APP_ERROR", exitCode = 1) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.exitCode = exitCode;
  }
}
