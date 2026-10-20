import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import { windowsNativeProcessApi } from "./WindowsNativeProcessApi.js";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";

// Every acknowledgement is emitted after both kernel membership and the
// birth-verified root handle have reached zero/signalled. A queued write is not proof.
const acknowledgementMs = 5000;
const script = `$ErrorActionPreference='Stop'; ${windowsNativeProcessApi}
$job=[IntPtr]::Zero; $root=[IntPtr]::Zero; $sequence=0
function Root-Exited { $state=$Native::WaitForSingleObject($root,0); if($state -eq 0){return $true}; if($state -eq 258){return $false}; throw 'ROOT_WAIT_UNAVAILABLE' }
function Active-Count { $b=[Runtime.InteropServices.Marshal]::AllocHGlobal(48); try { if(-not $Native::QueryInformationJobObject($job,1,$b,48,[IntPtr]::Zero)){throw 'JOB_QUERY_UNAVAILABLE'}; return [Runtime.InteropServices.Marshal]::ReadInt32($b,40) } finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($b) } }
function Stop-Job { if(-not $Native::TerminateJobObject($job,1)){throw 'JOB_TERMINATION_UNKNOWN'} }
function Confirm-Zero {
 $deadline=[DateTime]::UtcNow.AddMilliseconds(${acknowledgementMs})
 while((Active-Count) -ne 0 -or -not (Root-Exited)){if([DateTime]::UtcNow -ge $deadline){throw 'JOB_TERMINATION_UNACKNOWLEDGED'};Start-Sleep -Milliseconds 10}
}
try {
 $binding=[Console]::In.ReadLine() | ConvertFrom-Json
 $root=$Native::OpenProcess(0x101101,$false,[int]$binding.pid)
 if($root -eq [IntPtr]::Zero -or (Get-Birth $root) -ne [string]$binding.birth){throw 'JOB_IDENTITY_MISMATCH'}
 $job=$Native::CreateJobObjectW([IntPtr]::Zero,$null)
 if($job -eq [IntPtr]::Zero -or -not $Native::AssignProcessToJobObject($job,$root)){throw 'JOB_ASSIGNMENT_FAILED'}
 [Console]::Out.WriteLine('READY'); [Console]::Out.Flush()
 while($true){
  $line=[Console]::In.ReadLine()
  if($null -ne $line){
   if($line -notmatch '^(STOP|DRAIN|FINALIZE):([1-9][0-9]{0,8})$'){throw 'INVALID_CUSTODY_COMMAND'}
   $command=$Matches[1];$id=[int]$Matches[2];if($id -ne ($sequence+1)){throw 'CUSTODY_COMMAND_REPLAY'};$sequence=$id
  }else{$command='DRAIN';$id=0}
  if($command -eq 'STOP'){Stop-Job;Confirm-Zero;[Console]::Out.WriteLine("STOPPED:$($id):0");[Console]::Out.Flush();continue}
  if($command -eq 'FINALIZE' -and -not (Root-Exited)){throw 'ROOT_STILL_ALIVE'}
  $deadline=[DateTime]::UtcNow.AddMilliseconds(${workerRestorationGraceMs})
  while((Active-Count) -gt 0 -and -not (Root-Exited) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
  if((Active-Count) -gt 0){Stop-Job};Confirm-Zero
  if($null -ne $line){[Console]::Out.WriteLine("DRAINED:$($id):0");[Console]::Out.Flush()};break
 }
} finally { if($root -ne [IntPtr]::Zero){[void]$Native::CloseHandle($root)};if($job -ne [IntPtr]::Zero){[void]$Native::CloseHandle($job)} }
`;

export class WindowsWorkerJob {
  private readonly helper: ChildProcessWithoutNullStreams;
  private readonly ready: Promise<void>;
  private readonly closed: Promise<void>;
  private drained = false;
  private failure: Error | undefined;
  private stopped = false;
  private activeProcesses: number | undefined;
  private sequence = 0;
  private pending: { id: number; kind: "STOPPED" | "DRAINED"; resolve(): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> } | undefined;
  private stopping: Promise<void> | undefined;
  private draining: Promise<void> | undefined;
  private fail!: (reason: string) => void;
  public constructor(pid: number, birth: string, temp: string, onFailure: () => void = () => {}) {
    const windows = process.env.SystemRoot;
    if (process.platform !== "win32" || !windows || !Number.isSafeInteger(pid) || pid <= 0 || pid === process.pid || !/^\d{16,20}$/.test(birth)) throw Error("WINDOWS_JOB_BINDING_REFUSED");
    this.helper = spawn(join(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { windowsHide: true, env: { SystemRoot: windows, PATH: join(windows, "System32"), TEMP: temp, TMP: temp }, stdio: ["pipe", "pipe", "pipe"] });
    let resolveReady!: () => void, rejectReady!: (error: Error) => void;
    this.ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
    let ready = false, notified = false;
    this.fail = reason => {
      this.failure ??= Error(reason); clearTimeout(timeout);
      if (this.pending) { clearTimeout(this.pending.timer); this.pending.reject(this.failure); this.pending = undefined; }
      if (!ready) rejectReady(this.failure);
      if (ready && !notified) { notified = true; try { onFailure(); } catch { /* Custody remains permanently failed even if bookkeeping is unavailable. */ } }
    };
    const timeout = setTimeout(() => { this.fail("WINDOWS_JOB_ATTACH_TIMEOUT"); this.helper.kill("SIGKILL"); }, acknowledgementMs);
    let output = "", total = 0;
    this.helper.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString(); total += chunk.length;
      if (total > 4096) { this.fail("WINDOWS_JOB_OUTPUT_LIMIT"); this.helper.kill("SIGKILL"); return; }
      let end: number;
      while ((end = output.indexOf("\n")) >= 0) {
        const line = output.slice(0, end).replace(/\r$/, ""); output = output.slice(end + 1);
        if (line === "READY" && !ready) { ready = true; clearTimeout(timeout); resolveReady(); continue; }
        const frame = /^(STOPPED|DRAINED):([1-9][0-9]{0,8}):0$/.exec(line), pending = this.pending;
        if (!ready || !frame || !pending || frame[1] !== pending.kind || Number(frame[2]) !== pending.id) { this.fail("WINDOWS_JOB_PROTOCOL_FAILED"); this.helper.kill("SIGKILL"); return; }
        if (frame[1] === "STOPPED") this.stopped = true; else this.drained = true;
        this.activeProcesses = 0; clearTimeout(pending.timer); this.pending = undefined; pending.resolve();
      }
    });
    this.helper.stderr.resume();
    this.helper.stdin.on("error", () => this.fail("WINDOWS_JOB_PIPE_FAILED"));
    this.helper.on("error", () => this.fail("WINDOWS_JOB_HELPER_FAILED"));
    this.closed = new Promise(resolve => this.helper.once("close", code => {
      clearTimeout(timeout);
      if (!ready) this.fail("WINDOWS_JOB_ATTACH_FAILED");
      else if (code !== 0 || !this.drained || output.length) this.fail("WINDOWS_JOB_CUSTODY_UNKNOWN");
      resolve();
    }));
    this.helper.stdin.write(JSON.stringify({ pid, birth }) + "\n");
  }
  public async attached(): Promise<void> { await this.ready; }
  private command(command: "STOP" | "DRAIN" | "FINALIZE"): Promise<void> {
    if (this.failure) return Promise.reject(this.failure);
    if (this.pending || this.helper.exitCode !== null || this.helper.signalCode !== null) return Promise.reject(Error("WINDOWS_JOB_COMMAND_REFUSED"));
    return new Promise((resolve, reject) => {
      const id = ++this.sequence, timer = setTimeout(() => { this.fail("WINDOWS_JOB_ACK_TIMEOUT"); this.helper.kill("SIGKILL"); }, command === "DRAIN" ? workerRestorationGraceMs + acknowledgementMs : acknowledgementMs);
      this.pending = { id, kind: command === "STOP" ? "STOPPED" : "DRAINED", resolve, reject, timer };
      this.helper.stdin.write(command + ":" + id + "\n", error => { if (error) this.fail("WINDOWS_JOB_PIPE_FAILED"); });
    });
  }
  public terminate(): Promise<void> {
    if (this.stopping) return this.stopping;
    if (this.draining) return this.draining;
    this.stopping = (async () => { await this.ready; if (this.failure) throw this.failure; if (this.drained) return; await this.command("STOP"); })();
    return this.stopping;
  }
  public drain(voluntaryExit = false): Promise<void> {
    if (this.draining) return this.draining;
    this.draining = (async () => {
      try { await this.ready; if (this.stopping) await this.stopping; if (this.failure) throw this.failure; await this.command(voluntaryExit ? "FINALIZE" : "DRAIN"); }
      catch { /* The permanent failure is reported after the owned helper exits. */ }
      this.helper.stdin.end(); await this.closed; if (this.failure) throw this.failure;
    })();
    return this.draining;
  }
  public receipt(): Record<string, unknown> { return { kind: "WINDOWS_UNNAMED_JOB", helperPid: this.helper.pid, helperExitCode: this.helper.exitCode, drained: this.drained, stopped: this.stopped, terminationAcknowledged: this.stopped, activeProcesses: this.activeProcesses, failure: this.failure?.message, completeDescendantContainment: this.drained && !this.failure }; }
}
