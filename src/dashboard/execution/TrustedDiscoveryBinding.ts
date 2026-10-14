import type { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import type { ScanRequestLedger } from "../../core/http/ScanRequestLedger.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { randomBytes } from "node:crypto";
import { discoveryDeny, type DiscoveryDenialCode } from "./TrustedDiscoverySource.js";
export interface TrustedDiscoveryFacts {
  code: DiscoveryDenialCode | "SELECTED_FOR_REVIEW" | "ATTEMPTED" | "INITIATED" | "RESPONSE_OBSERVED" | "INCONCLUSIVE";
  attempted: number;
  initiated: number;
  responseObserved: number;
  auditEvents: number;
  scanReserved: number;
  assessment: "NOT_ASSESSED";
}
export function discoveryFacts(
  code: TrustedDiscoveryFacts["code"],
  attempted = 0,
  initiated = 0,
  responseObserved = 0,
  auditEvents = 0
): TrustedDiscoveryFacts {
  return {
    code,
    attempted,
    initiated,
    responseObserved,
    auditEvents,
    scanReserved: initiated,
    assessment: "NOT_ASSESSED"
  };
}
export interface TrustedDiscoveryOperation {
  broker: RequestSafetyBroker;
  scope: ScopeMatcher;
  ledger: ScanRequestLedger;
  owner: object;
  url: string;
  verify(): void;
  attempted: boolean;
  initiated: boolean;
  failure?: DiscoveryDenialCode;
  consumeAttempt(): void;
}
const operations = new WeakMap<object, TrustedDiscoveryOperation>();
const contexts = new WeakMap<object, { routes: Set<string>; attempted: boolean }>();
const consumedConsentReceipts = new WeakSet<object>();
const operationNonces = new WeakMap<object, Buffer>();
export function trustedDiscoveryContextState(context: object): { routes: Set<string>; attempted: boolean } {
  let state = contexts.get(context);
  if (!state) {
    state = { routes: new Set<string>(), attempted: false };
    contexts.set(context, state);
  }
  return state;
}
export function consumeTrustedDiscoveryConsent(receipt: unknown): void {
  if (!receipt || typeof receipt !== "object" || consumedConsentReceipts.has(receipt))
    discoveryDeny("DENIED_OPERATOR_BINDING");
  consumedConsentReceipts.add(receipt);
}
export function opaqueDiscoveryObject(): object {
  return Object.freeze(
    Object.defineProperty(Object.create(null) as object, "toJSON", {
      value: () => {
        throw new Error("PRIVATE_DISCOVERY_OBJECT_NOT_SERIALIZABLE");
      }
    })
  );
}
/** Native server-only construction. This module is never registered with a public endpoint or SDK. */
export function bindTrustedDiscoveryOperation(operation: TrustedDiscoveryOperation): object {
  const token = opaqueDiscoveryObject();
  operations.set(token, operation);
  operationNonces.set(token, randomBytes(32));
  return token;
}
export function claimTrustedDiscoveryOperation(
  token: unknown,
  broker: RequestSafetyBroker,
  scope: ScopeMatcher,
  ledger: ScanRequestLedger | undefined,
  owner?: object
): TrustedDiscoveryOperation {
  const op = token && typeof token === "object" ? operations.get(token) : undefined;
  if (
    !op ||
    !operationNonces.has(token as object) ||
    op.broker !== broker ||
    op.scope !== scope ||
    op.ledger !== ledger ||
    (owner && op.owner !== owner)
  )
    discoveryDeny("DENIED_OPERATOR_BINDING");
  if (op.attempted) discoveryDeny("DENIED_DUPLICATE");
  op.consumeAttempt();
  op.attempted = true;
  return op;
}
export function operationBelongsTo(token: unknown, owner: object): boolean {
  return !!token && typeof token === "object" && operations.get(token)?.owner === owner;
}
