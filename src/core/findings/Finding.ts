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
  | "Privilege Mutation Issue"
  | "Field Exposure Issue"
  | "Authorization Matrix Issue"
  | "Equivalent Route Authorization Issue"
  | "Collection Authorization Issue"
  | "Bulk Authorization Issue"
  | "File Authorization Issue"
  | "Supabase Authorization Issue"
  | "Supabase Configuration Risk"
  | "Authentication Lifecycle Issue"
  | "Business Logic Invariant Issue"
  | "Controlled Race Condition"
  | "API Authorization Issue"
  | "GraphQL Authorization Issue"
  | "API Method Confusion"
  | "GraphQL Introspection Exposure"
  | "GraphQL Limit Issue"
  | "API Schema Drift"
  | "API Version Boundary Issue"
  | "Signed Link Security Issue"
  | "Invitation Security Issue"
  | "Portal Tenant Isolation Issue"
  | "Export Authorization Issue"
  | "Evidence Artifact Authorization Issue"
  | "Object Path Authorization Issue"
  | "Webhook Security Issue"
  | "Cron Security Issue"
  | "Job Authorization Issue"
  | "Operational Endpoint Authorization Issue"
  | "Operational Information Exposure"
  | "Checkout Integrity Issue"
  | "Payment Entitlement Issue"
  | "Payment Event Idempotency Issue"
  | "Premium Access Authorization Issue"
  | "Subscription State Consistency Issue"
  | "Payment Event Race Condition"
  | "SQL Injection"
  | "NoSQL Injection"
  | "Cross-Site Scripting"
  | "Server-Side Request Forgery"
  | "Command Injection"
  | "Template Injection"
  | "Path Traversal"
  | "Cross-Site Request Forgery"
  | "Open Redirect"
  | "Cache Poisoning"
  | "Cache Deception"
  | "Unsafe Deserialization"
  | "XML External Entity Injection"
  | "HTTP Desynchronization"
  | "Server Credential Exposure"
  | "Session Secret Exposure"
  | "Client-Side Session Secret Exposure"
  | "Sensitive Response Exposure"
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

export type AssistedAssessmentOutcome = "PROVEN" | "INCONCLUSIVE" | "NOT_ASSESSED" | "BLOCKED";

export interface AssistedWorkflowFindingLinks {
  workflowId: string;
  caseId: string;
  evidenceRef: string;
  proofPackRefs: string[];
  proofPackReadiness: "REQUIRES_HUMAN_REVIEW";
  comparisonFingerprint?: string;
  assessmentOutcome: AssistedAssessmentOutcome;
  humanReviewState: "REQUIRED";
  cleanupOutcome?: string;
  cleanupFailed: boolean;
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
  workflow?: AssistedWorkflowFindingLinks;
  workflowCase?: { id: string; comparisonFingerprint?: string; cleanupOutcome?: string };
  customerSafeRemediation?: string;
}
