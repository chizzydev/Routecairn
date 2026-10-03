/** Authoring contract for the injected SDK. No runtime import or npm dependencies are required. */
export interface ModuleRequest {
  url: string; method?: "GET" | "HEAD" | "OPTIONS" | "POST"; purpose: string;
  headers?: Record<string, string>; body?: string; nonMutating?: boolean;
}
export interface ModuleResponse {
  schemaVersion: 1; outcome: "TRANSMITTED" | "POLICY_BLOCKED" | "BUDGET_BLOCKED" | "INCONCLUSIVE";
  safeUrl: string; method: string; statusCode?: number; statusClass?: string;
  headers: Record<string, string | string[]>; bodyPreview?: string; bodySha256?: string;
  bytesRead?: number; truncated?: boolean; responseTimeMs: number; redirectCount: number; errorCode?: string;
}
export interface ModuleFinding {
  title: string; category: string; severity: "Info" | "Low" | "Medium" | "High" | "Critical";
  confidence: "Low" | "Medium" | "High"; endpoint: string; description: string; remediation?: string;
}
export interface ModuleResult {
  observations: Array<{ kind: string; summary: string; data?: Record<string, string | number | boolean | null> }>;
  findings: ModuleFinding[]; notes: string[];
}
export interface ModuleSdk {
  readonly schemaVersion: 2;
  hash(value: unknown): Promise<string>;
  finding(value: ModuleFinding): Readonly<ModuleFinding>;
  request(value: ModuleRequest): Promise<ModuleResponse>;
  readonly capabilities: { readonly requestBroker: boolean; request(value: ModuleRequest): Promise<ModuleResponse> };
}
export type ModuleAnalyzer = (input: Record<string, unknown>, sdk: ModuleSdk) => Promise<ModuleResult>;
