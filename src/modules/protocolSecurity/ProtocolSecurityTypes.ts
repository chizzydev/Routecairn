import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const protocolSecurityKinds = [
  "WEBSOCKET", "SSE", "GRAPHQL_MUTATION", "GRAPHQL_SUBSCRIPTION",
  "WEBSOCKET_AUTH_STATE_MACHINE",
  "GRAPHQL_INCREMENTAL", "GRAPHQL_PERSISTED_QUERY", "GRAPHQL_FEDERATION", "GRAPHQL_SUBSCRIPTION_REAUTH",
  "GRPC_UNARY", "GRPC_SERVER_STREAM", "GRPC_CLIENT_STREAM", "GRPC_BIDI_STREAM", "MULTIPART_UPLOAD",
  "WEBTRANSPORT_DATAGRAM", "STREAMING_UPLOAD_INTERRUPT", "COMPRESSION_BOUNDARY", "CROSS_PROTOCOL_IDENTITY",
  "PROXY_CHAIN_DESYNCHRONIZATION",
  "HTTP2_AUTHORIZATION", "HTTP2_DESYNCHRONIZATION",
  "HTTP3_AUTHORIZATION", "HTTP3_DESYNCHRONIZATION"
] as const;
export type ProtocolSecurityKind = typeof protocolSecurityKinds[number];
export type ProtocolOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
export type ProtocolRiskClass = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
export type ProtocolActorSlot = "anonymous" | "primary" | "account_a" | "account_b";

export interface ProtocolActorPlan { id: string; safeAlias: string; authSlot: ProtocolActorSlot; relationship: string; }
export interface ProtocolExpectation { decision: "ALLOW" | "DENY" | "OBSERVE"; allowedStatuses: readonly number[]; deniedStatuses: readonly number[]; messageType?: string; jsonPath?: string; equals?: unknown; minMessages: number; }
export interface ProtocolCleanupPlan { url: string; method: HttpMethod; headers: Readonly<Record<string, string>>; body?: unknown; statusIn: readonly number[]; }
export interface ProtocolAuthorizationPlan { environment: "LOCAL" | "TEST" | "STAGING"; operator: string; ticket: string; authorizedAt: string; expiresAt: string; confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES"; disposableResources: true; }
export interface DesynchronizationAuthorizationPlan { environment: "LOCAL" | "TEST" | "STAGING"; operator: string; ticket: string; authorizedAt: string; expiresAt: string; confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION"; }

interface BaseCase { id: string; label: string; kind: ProtocolSecurityKind; actorId: string; requireVerifiedIdentity: boolean; url: string; headers: Readonly<Record<string, string>>; expectation: ProtocolExpectation; comparisonFingerprint: string; riskClass: ProtocolRiskClass; }
export interface WebSocketCasePlan extends BaseCase { kind: "WEBSOCKET"; subprotocols: readonly string[]; messages: readonly unknown[]; maxMessages: number; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface WebSocketStateStepPlan { send?: unknown; expectType?: string; expectJsonPath?: string; equals?: unknown; }
export interface WebSocketAuthStateMachineCasePlan extends BaseCase { kind: "WEBSOCKET_AUTH_STATE_MACHINE"; subprotocols: readonly string[]; states: readonly WebSocketStateStepPlan[]; maxMessages: number; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface SseCasePlan extends BaseCase { kind: "SSE"; method: "GET"; body?: undefined; maxEvents: number; }
export interface GraphqlMutationCasePlan extends BaseCase { kind: "GRAPHQL_MUTATION"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; authorization: ProtocolAuthorizationPlan; cleanup: ProtocolCleanupPlan; }
export interface GraphqlSubscriptionCasePlan extends BaseCase { kind: "GRAPHQL_SUBSCRIPTION"; transport: "GRAPHQL_TRANSPORT_WS" | "LEGACY_GRAPHQL_WS" | "SSE"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; connectionPayload?: unknown; maxMessages: number; }
export interface GraphqlIncrementalCasePlan extends BaseCase { kind: "GRAPHQL_INCREMENTAL"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; maxParts: number; expectedPaths: readonly string[]; }
export interface GraphqlPersistedQueryCasePlan extends BaseCase { kind: "GRAPHQL_PERSISTED_QUERY"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; sha256Hash: string; negotiation: "HASH_ONLY" | "REGISTER_THEN_HASH"; }
export interface GraphqlFederationCasePlan extends BaseCase { kind: "GRAPHQL_FEDERATION"; operation: "SERVICE_SDL" | "ENTITIES"; representations?: readonly Readonly<Record<string, unknown>>[]; }
export interface GraphqlSubscriptionReauthCasePlan extends BaseCase { kind: "GRAPHQL_SUBSCRIPTION_REAUTH"; transport: "GRAPHQL_TRANSPORT_WS" | "LEGACY_GRAPHQL_WS"; operationName?: string; document: string; variables: Readonly<Record<string, unknown>>; initialConnectionPayload?: unknown; reauthConnectionPayload: unknown; initialDecision: "ALLOW" | "DENY"; maxMessages: number; }
export interface GrpcCasePlan extends BaseCase { kind: "GRPC_UNARY" | "GRPC_SERVER_STREAM" | "GRPC_CLIENT_STREAM" | "GRPC_BIDI_STREAM"; payloadSecretRef?: string; payloadSecretRefs?: readonly string[]; maxMessages: number; interMessageDelayMs: number; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface MultipartFilePlan { fieldName: string; fileName: string; contentType: string; contentSecretRef: string; }
export interface MultipartCasePlan extends BaseCase { kind: "MULTIPART_UPLOAD"; fields: Readonly<Record<string, unknown>>; files: readonly MultipartFilePlan[]; readOnly: boolean; authorization?: ProtocolAuthorizationPlan; cleanup?: ProtocolCleanupPlan; }
export interface Http2AuthorizationCasePlan extends BaseCase { kind: "HTTP2_AUTHORIZATION"; method: "GET" | "HEAD" | "OPTIONS"; }
export interface Http2DesyncCasePlan extends BaseCase { kind: "HTTP2_DESYNCHRONIZATION"; method: "POST"; bodySecretRef: string; declaredLengthDelta: -1 | 1; sentinelPath: string; authorization: DesynchronizationAuthorizationPlan; }
export interface Http3AuthorizationCasePlan extends BaseCase { kind: "HTTP3_AUTHORIZATION"; method: "GET" | "HEAD" | "OPTIONS"; }
export interface Http3DesyncCasePlan extends BaseCase { kind: "HTTP3_DESYNCHRONIZATION"; method: "POST"; bodySecretRef: string; declaredLengthDelta: -1 | 1; sentinelPath: string; authorization: DesynchronizationAuthorizationPlan; }
export interface WebTransportDatagramCasePlan extends BaseCase { kind: "WEBTRANSPORT_DATAGRAM"; authenticationMode: "NONE" | "DATAGRAM"; datagramSecretRefs: readonly string[]; maxDatagrams: number; readOnly: true; }
export interface StreamingUploadInterruptCasePlan extends BaseCase { kind: "STREAMING_UPLOAD_INTERRUPT"; method: "POST" | "PUT" | "PATCH"; bodySecretRef: string; chunkBytes: number; interruptAfterBytes: number; verificationUrl: string; verificationMethod: "GET" | "HEAD"; authorization: ProtocolAuthorizationPlan; cleanup: ProtocolCleanupPlan; }
export interface CompressionBoundaryCasePlan extends BaseCase { kind: "COMPRESSION_BOUNDARY"; method: "GET" | "POST"; encoding: "gzip" | "deflate" | "br"; bodySecretRef?: string; maxExpandedBytes: number; readOnly: true; }
export interface CrossProtocolIdentityLegPlan { protocol: "HTTP1" | "HTTP2" | "HTTP3" | "WEBSOCKET" | "WEBTRANSPORT" | "GRPC"; url: string; method: "GET" | "HEAD" | "OPTIONS" | "POST"; headers: Readonly<Record<string, string>>; payloadSecretRef?: string; jsonPath?: string; }
export interface CrossProtocolIdentityCasePlan extends BaseCase { kind: "CROSS_PROTOCOL_IDENTITY"; legs: readonly [CrossProtocolIdentityLegPlan, CrossProtocolIdentityLegPlan, ...CrossProtocolIdentityLegPlan[]]; readOnly: true; }
export interface ProxyHopPlan { origin: string; protocol: "H1" | "H2" | "H3"; }
export interface ProxyChainDesyncCasePlan extends BaseCase { kind: "PROXY_CHAIN_DESYNCHRONIZATION"; method: "POST"; bodySecretRef: string; framing: "CONTENT_LENGTH_DELTA" | "CL_TE" | "TE_CL"; declaredLengthDelta: -1 | 1; sentinelPath: string; proxyChain: readonly ProxyHopPlan[]; authorization: DesynchronizationAuthorizationPlan; frontendProtocols?: readonly ("H1" | "H2" | "H3")[]; topologyProof?: { url: string; deploymentSha256: string; hopIds: readonly string[]; traceHeader: string; }; }
export type ProtocolSecurityCasePlan = WebSocketCasePlan | WebSocketAuthStateMachineCasePlan | SseCasePlan | GraphqlMutationCasePlan | GraphqlSubscriptionCasePlan | GraphqlIncrementalCasePlan | GraphqlPersistedQueryCasePlan | GraphqlFederationCasePlan | GraphqlSubscriptionReauthCasePlan | GrpcCasePlan | MultipartCasePlan | Http2AuthorizationCasePlan | Http2DesyncCasePlan | Http3AuthorizationCasePlan | Http3DesyncCasePlan | WebTransportDatagramCasePlan | StreamingUploadInterruptCasePlan | CompressionBoundaryCasePlan | CrossProtocolIdentityCasePlan | ProxyChainDesyncCasePlan;

export interface ProtocolSecurityPlan {
  schemaVersion: 1; enabled: true; targetOrigin: string; maxRequests: number; maxRequestBytes: number; maxResponseBytes: number; maxDurationMs: number;
  actors: readonly ProtocolActorPlan[]; cases: readonly ProtocolSecurityCasePlan[]; notes: readonly string[];
}

export interface ProtocolCaseObservation { caseId: string; label: string; kind: ProtocolSecurityKind; riskClass: ProtocolRiskClass; actorAlias: string; outcome: ProtocolOutcome; reason: string; statusCode?: number; negotiatedProtocol?: string; messageCount: number; eventCount: number; structuralCount?: number; cleanupOutcome?: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "NOT_REQUIRED"; comparisonFingerprint: string; }
export interface ProtocolSecurityReport { enabled: boolean; plannedCases: number; executedCases: number; passedCases: number; failedCases: number; inconclusiveCases: number; blockedCases: number; observations: readonly ProtocolCaseObservation[]; notes: readonly string[]; }
