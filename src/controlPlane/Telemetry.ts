import { context, metrics, SpanStatusCode, trace, type Span, type Tracer } from "@opentelemetry/api";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import type { ControlPlaneConfig } from "./ControlPlaneConfig.js";

type Fields = Record<string, string | number | boolean | null | undefined>;
const secretField = /(password|passwd|secret|token|cookie|authorization|private.?key|credential|session|jwt|signature)/i;

export class ControlPlaneTelemetry {
  private sdk?: NodeSDK;
  private readonly tracer: Tracer;
  private readonly requestCounter;
  private readonly jobCounter;
  private readonly duration;
  public constructor(private readonly config: ControlPlaneConfig["telemetry"]) {
    this.tracer = trace.getTracer(config.serviceName);
    const meter = metrics.getMeter(config.serviceName);
    this.requestCounter = meter.createCounter("routecairn.control_plane.requests");
    this.jobCounter = meter.createCounter("routecairn.control_plane.jobs");
    this.duration = meter.createHistogram("routecairn.control_plane.duration_ms", { unit: "ms" });
  }
  public async start(): Promise<void> {
    if (!this.config.otlpEndpoint) return;
    const base = this.config.otlpEndpoint.replace(/\/$/, "");
    this.sdk = new NodeSDK({
      serviceName: this.config.serviceName,
      traceExporter: new OTLPTraceExporter({ url: `${base}/v1/traces` }),
      metricReader: new PeriodicExportingMetricReader({ exporter: new OTLPMetricExporter({ url: `${base}/v1/metrics` }), exportIntervalMillis: 15_000 })
    });
    await this.sdk.start();
  }
  public countRequest(route: string, status: number): void { this.requestCounter.add(1, { route: safeLabel(route), status: String(status) }); }
  public countJob(kind: string, state: string): void { this.jobCounter.add(1, { kind: safeLabel(kind), state: safeLabel(state) }); }
  public recordDuration(operation: string, milliseconds: number): void { this.duration.record(milliseconds, { operation: safeLabel(operation) }); }
  public startSpan(name: string, fields: Fields): Span { return this.tracer.startSpan(name, { attributes: sanitize(fields) }); }
  public async span<T>(name: string, fields: Fields, work: (span: Span) => Promise<T>): Promise<T> {
    return this.tracer.startActiveSpan(name, { attributes: sanitize(fields) }, context.active(), async (span) => {
      const started = performance.now();
      try { const result = await work(span); span.setStatus({ code: SpanStatusCode.OK }); return result; }
      catch (error) { span.setStatus({ code: SpanStatusCode.ERROR, message: safeError(error) }); throw error; }
      finally { this.recordDuration(name, performance.now() - started); span.end(); }
    });
  }
  public log(level: "debug" | "info" | "warn" | "error", message: string, fields: Fields = {}): void {
    const order = { debug: 10, info: 20, warn: 30, error: 40 } as const;
    if (order[level] < order[this.config.logLevel]) return;
    process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), severity: level.toUpperCase(), service: this.config.serviceName, message: safeMessage(message), traceId: trace.getSpan(context.active())?.spanContext().traceId, ...sanitize(fields) })}\n`);
  }
  public async shutdown(): Promise<void> { await this.sdk?.shutdown(); }
}

function sanitize(fields: Fields): Record<string, string | number | boolean> {
  return Object.fromEntries(Object.entries(fields).filter(([key, item]) => !secretField.test(key) && item !== undefined && item !== null).map(([key, item]) => [safeLabel(key), typeof item === "string" ? safeMessage(item) : item as number | boolean]));
}
function safeLabel(value: string): string { return value.replace(/[\r\n\u0000-\u001f]/g, " ").slice(0, 200); }
function safeMessage(value: string): string { return safeLabel(value).replace(/https?:\/\/[^\s]+/gi, "<endpoint>").replace(/\b(password|secret|token|cookie|authorization|private.?key|credential|session|jwt|signature)\s*[:=]\s*[^\s,;]+/gi,"$1=<redacted>"); }
function safeError(error: unknown): string { return safeMessage(error instanceof Error ? error.message : "operation failed"); }
