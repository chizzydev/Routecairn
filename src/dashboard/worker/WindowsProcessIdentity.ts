import { execFile } from "node:child_process";
import { join } from "node:path";
import { windowsNativeProcessApi } from "./WindowsNativeProcessApi.js";

export interface WindowsProcessIdentity { pid: number; parentPid: number; birth: string; }
// Read-only native birth lookup. No compilation or termination authority.
export const windowsProcessBirthScript = `$ErrorActionPreference='Stop'; ${windowsNativeProcessApi}
$inputData=[Console]::In.ReadToEnd() | ConvertFrom-Json
$handle=$Native::OpenProcess(0x1000,$false,[int]$inputData.pid)
if($handle -eq [IntPtr]::Zero){ $code=$Native::GetLastError(); if($code -eq 87 -or $code -eq 1168){ [Console]::Out.WriteLine('null') } else { throw 'PROCESS_QUERY_UNAVAILABLE' } }
else { try { ConvertTo-Json -InputObject (Get-Birth $handle) -Compress } finally { [void]$Native::CloseHandle($handle) } }
`;

async function invoke(input: Record<string, unknown>, temp: string): Promise<unknown> {
  if (process.platform !== "win32") throw Error("WINDOWS_PROCESS_IDENTITY_ONLY");
  const windows = process.env.SystemRoot;
  if (!windows) throw Error("WINDOWS_DIRECTORY_UNAVAILABLE");
  return new Promise((resolve, reject) => {
    const child = execFile(join(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(windowsProcessBirthScript, "utf16le").toString("base64")], { timeout: 5000, maxBuffer: 8192, windowsHide: true, env: { SystemRoot: windows, PATH: join(windows, "System32"), TEMP: temp, TMP: temp } }, (error, stdout) => {
      if (error) { reject(Error("WINDOWS_PROCESS_IDENTITY_UNAVAILABLE:" + error.code)); return; }
      try { resolve(JSON.parse(stdout.replace(/^\ufeff/, "").trim())); } catch { reject(Error("WINDOWS_PROCESS_IDENTITY_INVALID")); }
    });
    child.stdin?.on("error", () => { /* execFile completion reports the helper failure. */ });
    child.stdin?.end(JSON.stringify(input));
  });
}
export async function windowsProcessBirth(pid: number, temp: string): Promise<string | null> {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw Error("WINDOWS_PROCESS_PID_INVALID");
  const value = await invoke({ action: "birth", pid }, temp);
  if (value === null) return null;
  if (typeof value !== "string" || !/^\d{16,20}$/.test(value)) throw Error("WINDOWS_PROCESS_BIRTH_INVALID");
  return value;
}
