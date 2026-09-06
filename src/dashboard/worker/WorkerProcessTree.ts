import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type SupportedWorkerPlatform = "win32" | "linux" | "darwin";

export interface ProcessRecord { pid: number; parentPid: number; }

export function workerProcessTreePlan(rootPid: number, platform: SupportedWorkerPlatform, force: boolean): { discovery: { file: string; args: string[] }; termination: { kind: "command"; file: string; args: string[] } | { kind: "process-group"; pid: number; signal: "SIGTERM" | "SIGKILL" } } {
  if (!Number.isSafeInteger(rootPid) || rootPid <= 0) throw new Error("Invalid worker process ID.");
  return platform === "win32" ? {
    discovery: { file: "powershell.exe", args: ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Process"] },
    termination: { kind: "command", file: "taskkill.exe", args: ["/PID", String(rootPid), "/T", ...(force ? ["/F"] : [])] }
  } : {
    discovery: { file: "ps", args: ["-axo", "pid=,ppid="] },
    termination: { kind: "process-group", pid: -rootPid, signal: force ? "SIGKILL" : "SIGTERM" }
  };
}

export function descendantProcessIds(records: readonly ProcessRecord[], rootPid: number): number[] {
  const result: number[] = [];
  const pending = [rootPid];
  const seen = new Set(pending);
  while (pending.length) {
    const parent = pending.shift()!;
    for (const record of records) {
      if (record.parentPid !== parent || seen.has(record.pid)) continue;
      seen.add(record.pid);
      result.push(record.pid);
      pending.push(record.pid);
    }
  }
  return result;
}

export function parseWindowsProcessCsv(output: string): ProcessRecord[] {
  return output.split(/\r?\n/).flatMap((line) => {
    const match = /^"?(\d+)"?,"?(\d+)"?$/.exec(line.trim());
    return match ? [{ pid: Number(match[1]), parentPid: Number(match[2]) }] : [];
  });
}

export function parsePosixProcessList(output: string): ProcessRecord[] {
  return output.split(/\r?\n/).flatMap((line) => {
    const match = /^\s*(\d+)\s+(\d+)\s*$/.exec(line);
    return match ? [{ pid: Number(match[1]), parentPid: Number(match[2]) }] : [];
  });
}

export async function processTreeIds(rootPid: number, platform: NodeJS.Platform = process.platform): Promise<number[]> {
  if (!Number.isSafeInteger(rootPid) || rootPid <= 0) return [];
  try {
    if (platform === "win32") {
      const plan = workerProcessTreePlan(rootPid, "win32", false);
      const { stdout } = await execFileAsync(plan.discovery.file, ["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Process | ForEach-Object { '\"{0}\",\"{1}\"' -f $_.ProcessId,$_.ParentProcessId }"]);
      return [rootPid, ...descendantProcessIds(parseWindowsProcessCsv(stdout), rootPid)];
    }
    const plan = workerProcessTreePlan(rootPid, platform === "darwin" ? "darwin" : "linux", false);
    const { stdout } = await execFileAsync(plan.discovery.file, plan.discovery.args);
    return [rootPid, ...descendantProcessIds(parsePosixProcessList(stdout), rootPid)];
  } catch {
    return [rootPid];
  }
}

export async function terminateProcessTree(rootPid: number, force: boolean, platform: NodeJS.Platform = process.platform): Promise<void> {
  if (!Number.isSafeInteger(rootPid) || rootPid <= 0 || rootPid === process.pid) throw new Error("Refusing unsafe process-tree termination target.");
  const plan = workerProcessTreePlan(rootPid, platform === "win32" ? "win32" : platform === "darwin" ? "darwin" : "linux", force);
  if (plan.termination.kind === "command") {
    await execFileAsync(plan.termination.file, plan.termination.args).catch((error: unknown) => {
      if (processAlive(rootPid)) throw error;
    });
    return;
  }
  try { process.kill(plan.termination.pid, plan.termination.signal); }
  catch (error) { if (processAlive(rootPid)) throw error; }
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return !(error && typeof error === "object" && "code" in error && error.code === "ESRCH"); }
}
