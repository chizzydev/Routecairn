import { readFile } from "node:fs/promises";
import { routeCairnConfigSchema, scopeSchema, type RouteCairnConfig, type RouteCairnScope } from "./ConfigSchema.js";
import { AppError } from "../core/errors/AppError.js";

export async function loadRouteCairnConfig(filePath: string): Promise<RouteCairnConfig> {
  const raw = await readJsonFile(filePath);
  const parsed = routeCairnConfigSchema.safeParse(raw);

  if (!parsed.success) {
    throw new AppError(`Invalid RouteCairn config: ${parsed.error.message}`, "CONFIG_INVALID");
  }

  return parsed.data;
}

export async function loadScope(filePath: string): Promise<RouteCairnScope> {
  const raw = await readJsonFile(filePath);
  const parsed = scopeSchema.safeParse(raw);

  if (!parsed.success) {
    throw new AppError(`Invalid RouteCairn scope: ${parsed.error.message}`, "SCOPE_INVALID");
  }

  return parsed.data;
}

async function readJsonFile(filePath: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(filePath, "utf8")) as unknown;
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new AppError(`Invalid JSON in ${filePath}: ${error.message}`, "JSON_INVALID");
    }

    throw error;
  }
}
