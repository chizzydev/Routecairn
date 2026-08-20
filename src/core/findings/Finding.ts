import type { Confidence } from "./Confidence.js";
import type { Severity } from "./Severity.js";
import type { FalsePositiveStatus } from "../../reports/ReportTypes.js";
import type { ValuePresenceAttestation } from "../evidence/ValuePresenceAttestation.js";

export type FindingType =
  | "Admin/Login Panel"
  | "API Endpoint"
  | "GraphQL Endpoint"
  | "Security Header Issue"
  | "Cookie Issue"
  | "CORS Issue"
  | "HTTP Method Issue"
  | "Object Authorization Issue"
  | "Field Exposure Issue"
  | "Authorization Matrix Issue"
  | "Equivalent Route Authorization Issue"
  | "Collection Authorization Issue"
  | "Bulk Authorization Issue"
  | "File Authorization Issue"
  | "Sensitive File Exposure"
  | "Backup File Exposure"
  | "Config Exposure"
  | "Debug/Dev Path"
  | "Directory Listing"
  | "Source Map Exposure"
  | "Next.js Public Serialized Sensitive Data Exposure"
  | "Next.js Source Map Sensitive Data Exposure"
  | "Next.js Public Runtime Secret Exposure"
  | "Next.js Cross-Actor Data Exposure"
  | "Next.js Shared Cache Private Data Exposure"
  | "Public Cloud Reference"
  | "Interesting But Needs Manual Testing";

export interface FindingEvidence {
  url: string;
  method: string;
  statusCode?: number;
  title?: string;
  source?: string;
  bodyHash?: string;
  contentType?: string;
  contentLength?: number;
  responseHeaders?: Record<string, string | string[]>;
  bodyPreview?: string;
  curlCommand?: string;
  severityReason?: string;
  reproductionNotes?: string[];
  valueAttestations?: readonly ValuePresenceAttestation[];
}

export interface Finding {
  id: string;
  title: string;
  type: FindingType;
  severity: Severity;
  confidence: Confidence;
  url: string;
  method: string;
  statusCode?: number;
  evidence: FindingEvidence;
  impact: string;
  recommendation: string;
  manualTestingSuggestions: string[];
  tags: string[];
  riskScore: number;
  sourceModule: string;
  falsePositiveStatus: FalsePositiveStatus;
  timestamp: string;
}
