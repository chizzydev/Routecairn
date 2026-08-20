import type { HttpResponse } from "./HttpTypes.js";

type AnalysisHeaders = Readonly<Record<string, string | readonly string[]>>;

interface TransientResponseAnalysis {
  readonly headers: AnalysisHeaders;
  readonly bodyPreview?: string;
}

const transientAnalysisByResponse = new WeakMap<HttpResponse, TransientResponseAnalysis>();

export function attachTransientResponseAnalysis(safeResponse: HttpResponse, rawResponse: HttpResponse): HttpResponse {
  transientAnalysisByResponse.set(safeResponse, {
    headers: cloneHeaders(rawResponse.headers),
    ...(typeof rawResponse.bodyPreview === "string" ? { bodyPreview: rawResponse.bodyPreview } : {})
  });
  return safeResponse;
}

export function copyTransientResponseAnalysis(source: HttpResponse, target: HttpResponse): HttpResponse {
  const analysis = transientAnalysisByResponse.get(source);
  if (analysis) {
    transientAnalysisByResponse.set(target, analysis);
  }
  return target;
}

export function bodyPreviewForAnalysis(response: HttpResponse): string | undefined {
  return transientAnalysisByResponse.get(response)?.bodyPreview ?? response.bodyPreview;
}

export function headersForAnalysis(response: HttpResponse): AnalysisHeaders {
  return transientAnalysisByResponse.get(response)?.headers ?? response.headers;
}

function cloneHeaders(headers: HttpResponse["headers"]): AnalysisHeaders {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(headers).map(([name, value]) => [name, Array.isArray(value) ? Object.freeze([...value]) : value])
    )
  );
}
