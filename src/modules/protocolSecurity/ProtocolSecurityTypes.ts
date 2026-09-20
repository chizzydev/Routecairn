import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const protocolSecurityKinds = [
  "WEBSOCKET", "SSE", "GRAPHQL_MUTATION", "GRAPHQL_SUBSCRIPTION",
  "GRPC_UNARY", "GRPC_SERVER_STREAM", "MULTIPART_UPLOAD",
  "HTTP2_AUTHORIZATION", "HTTP2_DESYNCHRONIZATION",
  "HTTP3_AUTHORIZATION", "HTTP3_DESYNCHRONIZATION"
] as const;
export type ProtocolSecurityKind = typeof protocolSecurityKinds[number];
export type ProtocolOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
export type ProtocolActorSlot = "anonymous" | "primary" | "account_a" | "account_b";

export interface ProtocolActorPlan { id: string; safeAlias: string; authSlot: ProtocolActorSlot; relationship: string; }
export interface ProtocolExpectation { decision: "ALLOW" | "DENY" | "OBSERVE"; allowedStatuses: readonly number[]; deniedStatuses: readonly number[]; messageType?: string; jsonPath?: string; equals?: unknown; minMessages: number; }
export interface ProtocolCleanupPlan { url: string; method: HttpMethod; headers: Readonly<Record<string, string>>; body?: unknown; statusIn: readonly number[]; }
export interface ProtocolAuthorizationPlan { environment: "LOCAL" | "TEST" | "STAGING"; operator: string; ticket: string; authorizedAt: string; expiresAt: string; confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES"; disposableResources: true; }
export interface DesynchronizationAuthorizationPlan { environment: "LOCAL" | "TEST" | "STAGING"; operator: string; ticket: string; authorizedAt: string; expiresAt: string; confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION"; }

interface BaseCase { id: string; label: string; kind: ProtocolSecurityKind; actorId: string; requireVerifiedIdentity: boolean; url: string; headers: Readonly<Record<string, string>>; expectation: ProtocolExpectation; comparisonFingerprint: string; }
export interface WebSocketCasePlan extends BaseCase { kind: "WEBSOCKET"; subprotocols: readonly string[]; messages: readonly unknown[]; maxMessages: number; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface SseCasePlan extends BaseCase { kind: "SSE"; method: "GET"; body?: undefined; maxEvents: number; }
export interface GraphqlMutationCasePlan extends BaseCase { kind: "GRAPHQL_MUTATION"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; authorization: ProtocolAuthorizationPlan; cleanup: ProtocolCleanupPlan; }
export interface GraphqlSubscriptionCasePlan extends BaseCase { kind: "GRAPHQL_SUBSCRIPTION"; transport: "GRAPHQL_TRANSPORT_WS" | "LEGACY_GRAPHQL_WS" | "SSE"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; connectionPayload?: unknown; maxMessages: number; }
export interface GrpcCasePlan extends BaseCase { kind: "GRPC_UNARY" | "GRPC_SERVER_STREAM"; payloadSecretRef: string; maxMessages: number; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface MultipartFilePlan { fieldName: string; fileName: string; contentType: string; contentSecretRef: string; }
export interface MultipartCasePlan extends BaseCase { kind: "MULTIPART_UPLOAD"; fields: Readonly<Record<string, unknown>>; files: readonly MultipartFilePlan[]; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface Http2AuthorizationCasePlan extends BaseCase { kind: "HTTP2_AUTHORIZATION"; method: "GET" | "HEAD" | "OPTIONS"; }
export interface Http2DesyncCasePlan extends BaseCase { kind: "HTTP2_DESYNCHRONIZATION"; method: "POST"; bodySecretRef: string; declaredLengthDelta: -1 | 1; sentinelPath: string; authorization: DesynchronizationAuthorizationPlan; }
export interface Http3AuthorizationCasePlan extends BaseCase { kind: "HTTP3_AUTHORIZATION"; method: "GET" | "HEAD" | "OPTIONS"; }
export interface Http3DesyncCasePlan extends BaseCase { kind: "HTTP3_DESYNCHRONIZATION"; method: "POST"; bodySecretRef: string; declaredLengthDelta: -1 | 1; sentinelPath: string; authorization: DesynchronizationAuthorizationPlan; }
export type ProtocolSecurityCasePlan = WebSocketCasePlan | SseCasePlan | GraphqlMutationCasePlan | GraphqlSubscriptionCasePlan | GrpcCasePlan | MultipartCasePlan | Http2AuthorizationCasePlan | Http2DesyncCasePlan | Http3AuthorizationCasePlan | Http3DesyncCasePlan;

export interface ProtocolSecurityPlan {
  schemaVersion: 1; enabled: true; targetOrigin: string; maxRequests: number; maxRequestBytes: number; maxResponseBytes: number; maxDurationMs: number;
  actors: readonly ProtocolActorPlan[]; cases: readonly ProtocolSecurityCasePlan[]; notes: readonly string[];
}

export interface ProtocolCaseObservation { caseId: string; label: string; kind: ProtocolSecurityKind; actorAlias: string; outcome: ProtocolOutcome; reason: string; statusCode?: number; negotiatedProtocol?: string; messageCount: number; eventCount: number; cleanupOutcome?: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "NOT_REQUIRED"; comparisonFingerprint: string; }
export interface ProtocolSecurityReport { enabled: boolean; plannedCases: number; executedCases: number; passedCases: number; failedCases: number; inconclusiveCases: number; blockedCases: number; observations: readonly ProtocolCaseObservation[]; notes: readonly string[]; }
