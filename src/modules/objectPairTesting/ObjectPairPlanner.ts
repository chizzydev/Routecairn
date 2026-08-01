import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  ObjectAccessTemplatePlan,
  ObjectOwnershipAssertionPlan,
  ObjectPairCasePlan,
  ObjectPairPrincipalPlan,
  ObjectPairRequestPlan,
  ObjectPairTestingPlan,
  ObjectVisibilityExpectation
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";

const objectPlaceholder = "{{OBJECT_ID}}";
const encodedObjectPlaceholder = "%7B%7BOBJECT_ID%7D%7D";
const tenantPlaceholder = "{{TENANT_ID}}";
const encodedTenantPlaceholder = "%7B%7BTENANT_ID%7D%7D";
const maxDefaultPairs = 5;
const maxObjectPairFileBytes = 256 * 1024;
const maxCaseCount = 20;
const maxIdentifierLength = 256;
const maxTemplateLength = 2048;
const forbiddenEndpointWords = /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read)/i;
const generatorPattern = /(?:\.\.|\*|\[|\]|\{|\}|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|prefix|suffix|eval|for\s*\(|while\s*\()/i;
const numericRangePattern = /^\s*\d+\s*-\s*\d+\s*$/;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;
const fieldPathPattern = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,5}$/;
const headerNamePattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

const visibilitySchema = z.enum(["PRIVATE_TO_OWNER", "SHARED_WITH_SPECIFIC_PRINCIPALS", "TENANT_VISIBLE", "ROLE_VISIBLE", "PUBLIC", "UNKNOWN_REQUIRES_REVIEW"]);

const objectAssertionSchema = z.object({
  id: z.string().min(1).max(maxIdentifierLength),
  source: z.string().min(1).max(512),
  confirmedSafeToTest: z.literal(true),
  readOnly: z.literal(true),
  tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
  expectedObjectIdField: z.string().min(1).max(160).optional(),
  expectedOwnerField: z.string().min(1).max(160).optional(),
  expectedTenantField: z.string().min(1).max(160).optional(),
  expectedObjectIdHeader: z.string().min(1).max(80).optional(),
  expectedOwnerHeader: z.string().min(1).max(80).optional(),
  expectedPrivateHeaders: z.array(z.string().min(1).max(80)).max(10).default([]),
  expectedSafeMarkers: z.array(z.string().min(1).max(256)).max(20).default([]),
  expectedPrivateFields: z.array(z.string().min(1).max(160)).max(20).default([])
}).strict();

const caseSchema = z.object({
  id: z.string().min(1).max(120),
  objectType: z.string().min(1).max(80),
  expectedVisibility: visibilitySchema.default("PRIVATE_TO_OWNER"),
  template: z.object({
    id: z.string().min(1).max(120),
    method: z.enum(["GET", "HEAD"]),
    url: z.string().min(1).max(maxTemplateLength),
    headers: z.record(z.string().max(512)).default({})
  }).strict(),
  accountAObject: objectAssertionSchema,
  accountBObject: objectAssertionSchema
}).strict();

const objectPairInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxPairs: z.number().int().positive().max(20).default(maxDefaultPairs),
  principals: z
    .object({
      accountA: z
        .object({
          expectedAccountId: z.string().min(1).max(maxIdentifierLength).optional(),
          tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
          role: z.string().min(1).max(80).optional()
        })
        .strict()
        .default({}),
      accountB: z
        .object({
          expectedAccountId: z.string().min(1).max(maxIdentifierLength).optional(),
          tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
          role: z.string().min(1).max(80).optional()
        })
        .strict()
        .default({})
    })
    .strict()
    .default({ accountA: {}, accountB: {} }),
  cases: z.array(caseSchema).min(1).max(maxCaseCount)
}).strict();

export type ObjectPairInput = z.infer<typeof objectPairInputSchema>;

export async function loadObjectPairInput(filePath: string): Promise<ObjectPairInput> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength > maxObjectPairFileBytes) {
    throw new AppError(`Object pair input exceeds maximum size ${maxObjectPairFileBytes} bytes.`, "OBJECT_PAIR_FILE_TOO_LARGE");
  }

  const raw = rawBuffer.toString("utf8").replace(/^\uFEFF/, "");
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new AppError("Object pair input is not valid JSON.", "OBJECT_PAIR_JSON_INVALID");
  }

  const parsed = objectPairInputSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "OBJECT_PAIR_INPUT_INVALID");
  }
  return parsed.data;
}

export function planObjectPairTesting(input: ObjectPairInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): ObjectPairTestingPlan {
  if (!options.authProfileSet) {
    throw new AppError("Object pair testing requires --auth-a and --auth-b.", "OBJECT_PAIR_AUTH_PAIR_REQUIRED");
  }

  const profileSet = options.authProfileSet;
  validateDeclaredPrincipalIdentity(profileSet, input.principals);
  validateDistinctPrincipals(profileSet);
  const principalA = requirePrincipalId(profileSet.accountA.principalId, "Account A");
  const principalB = requirePrincipalId(profileSet.accountB.principalId, "Account B");
  validateInputUniqueness(input);
  if (input.cases.length > input.maxPairs) {
    throw new AppError(`Object pair input contains ${input.cases.length} cases, exceeding maxPairs ${input.maxPairs}.`, "OBJECT_PAIR_TOO_MANY_CASES");
  }

  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const principals: ObjectPairPrincipalPlan[] = [
    {
      label: "account_a",
      redactedLabel: profileSet.accountA.safeAlias ?? profileSet.accountA.label,
      principalIdHash: objectIdHash(principalA),
      ...(profileSet.accountA.tenantId ? { tenantIdHash: objectIdHash(profileSet.accountA.tenantId) } : {}),
      ...optionalRole(profileSet.accountA.role ?? input.principals.accountA.role)
    },
    {
      label: "account_b",
      redactedLabel: profileSet.accountB.safeAlias ?? profileSet.accountB.label,
      principalIdHash: objectIdHash(principalB),
      ...(profileSet.accountB.tenantId ? { tenantIdHash: objectIdHash(profileSet.accountB.tenantId) } : {}),
      ...optionalRole(profileSet.accountB.role ?? input.principals.accountB.role)
    }
  ];

  const cases = input.cases.map((testCase) => planCase(testCase, scopeMatcher, principalPlanningInput(input.principals, profileSet)));
  const requestMatrix = cases.flatMap((testCase) => [...testCase.requestMatrix]);

  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    principals,
    cases,
    requestMatrix,
    maxPairs: input.maxPairs,
    maxRequests: requestMatrix.length,
    notes: [
      "Object pair testing uses only explicitly supplied object identifiers.",
      "The request matrix is fixed during planning; runtime responses do not create new test cases.",
      "Only GET and HEAD URL templates are supported in this version."
    ]
  });
}

function optionalRole(role: string | undefined): { role?: string } {
  return role ? { role } : {};
}

function planCase(testCase: ObjectPairInput["cases"][number], scopeMatcher: ScopeMatcher, principals: ObjectPairInput["principals"]): ObjectPairCasePlan {
  validateIdentifier(testCase.accountAObject.id, `${testCase.id}.accountAObject.id`);
  validateIdentifier(testCase.accountBObject.id, `${testCase.id}.accountBObject.id`);
  validateAssertionEvidence(testCase.accountAObject, `${testCase.id}.accountAObject`);
  validateAssertionEvidence(testCase.accountBObject, `${testCase.id}.accountBObject`);
  if (testCase.accountAObject.id === testCase.accountBObject.id) {
    throw new AppError(`Object pair case "${testCase.id}" uses the same object ID for Account A and Account B.`, "OBJECT_PAIR_IDENTICAL_OBJECTS");
  }

  validateTemplate(testCase.template);
  const template: ObjectAccessTemplatePlan = {
    id: testCase.template.id,
    method: testCase.template.method,
    urlTemplate: testCase.template.url,
    headers: testCase.template.headers
  };

  const accountAObject = ownershipAssertion(testCase.accountAObject, testCase.objectType, "account_a", testCase.expectedVisibility, principals.accountA);
  const accountBObject = ownershipAssertion(testCase.accountBObject, testCase.objectType, "account_b", testCase.expectedVisibility, principals.accountB);

  const requestMatrix: ObjectPairRequestPlan[] = [
    requestPlan(testCase.id, "A_TO_A", "owner-baseline", "account_a", accountAObject, template, scopeMatcher),
    requestPlan(testCase.id, "B_TO_B", "owner-baseline", "account_b", accountBObject, template, scopeMatcher),
    requestPlan(testCase.id, "A_TO_B", "cross-account", "account_a", accountBObject, template, scopeMatcher),
    requestPlan(testCase.id, "B_TO_A", "cross-account", "account_b", accountAObject, template, scopeMatcher)
  ];

  return {
    id: testCase.id,
    objectType: testCase.objectType,
    template,
    accountAObject,
    accountBObject,
    requestMatrix
  };
}

function ownershipAssertion(
  assertion: ObjectPairInput["cases"][number]["accountAObject"],
  objectType: string,
  owner: "account_a" | "account_b",
  expectedVisibility: ObjectVisibilityExpectation,
  principal: ObjectPairInput["principals"]["accountA"]
): ObjectOwnershipAssertionPlan {
  const expectedTenantValue = assertion.tenantId ?? principal.tenantId;
  return {
    objectId: assertion.id,
    objectIdHash: objectIdHash(assertion.id),
    objectType,
    owner,
    expectedVisibility,
    confirmedSafeToTest: true,
    readOnly: true,
    source: assertion.source,
    ...(assertion.expectedObjectIdField ? { expectedObjectIdField: assertion.expectedObjectIdField } : {}),
    ...(assertion.expectedOwnerField ? { expectedOwnerField: assertion.expectedOwnerField } : {}),
    ...(principal.expectedAccountId ? { expectedOwnerValue: principal.expectedAccountId } : {}),
    ...(assertion.expectedTenantField ? { expectedTenantField: assertion.expectedTenantField } : {}),
    ...(expectedTenantValue ? { expectedTenantValue } : {}),
    ...(assertion.expectedObjectIdHeader ? { expectedObjectIdHeader: assertion.expectedObjectIdHeader } : {}),
    ...(assertion.expectedOwnerHeader ? { expectedOwnerHeader: assertion.expectedOwnerHeader } : {}),
    expectedPrivateHeaders: assertion.expectedPrivateHeaders ?? [],
    expectedSafeMarkers: assertion.expectedSafeMarkers,
    expectedPrivateFields: assertion.expectedPrivateFields
  };
}

function requestPlan(
  caseId: string,
  direction: ObjectPairRequestPlan["direction"],
  purpose: ObjectPairRequestPlan["purpose"],
  requestingPrincipal: "account_a" | "account_b",
  targetObject: ObjectOwnershipAssertionPlan,
  template: ObjectAccessTemplatePlan,
  scopeMatcher: ScopeMatcher
): ObjectPairRequestPlan {
  const url = applyObjectPlaceholder(template.urlTemplate, targetObject.objectId);
  const decision = scopeMatcher.decide(url, template.method);
  if (!decision.allowed || !decision.normalizedUrl) {
    throw new AppError(`Object pair request "${caseId}:${direction}" is out of scope: ${decision.reason}.`, "OBJECT_PAIR_OUT_OF_SCOPE");
  }

  return {
    id: `${caseId}:${direction}`,
    caseId,
    direction,
    purpose,
    requestingPrincipal,
    targetOwner: targetObject.owner,
    targetObjectId: targetObject.objectId,
    targetObjectIdHash: targetObject.objectIdHash,
    objectType: targetObject.objectType,
    expectedVisibility: targetObject.expectedVisibility,
    method: template.method,
    url: decision.normalizedUrl
  };
}

function validateTemplate(template: ObjectPairInput["cases"][number]["template"]): void {
  if (template.url.length > maxTemplateLength) {
    throw new AppError(`Object pair template "${template.id}" exceeds maximum URL template length.`, "OBJECT_PAIR_TEMPLATE_TOO_LONG");
  }

  const decodedUrl = decodeTemplatePlaceholders(template.url);
  if ((decodedUrl.match(/\{\{[A-Z_]+\}\}/g) ?? []).some((placeholder) => placeholder !== objectPlaceholder && placeholder !== tenantPlaceholder)) {
    throw new AppError(`Object pair template "${template.id}" contains an undeclared placeholder.`, "OBJECT_PAIR_TEMPLATE_INVALID");
  }

  const objectPlaceholderCount = (decodedUrl.match(/\{\{OBJECT_ID\}\}/g) ?? []).length;
  if (objectPlaceholderCount !== 1) {
    throw new AppError(`Object pair template "${template.id}" must contain exactly one {{OBJECT_ID}} placeholder.`, "OBJECT_PAIR_TEMPLATE_PLACEHOLDER_INVALID");
  }

  if (decodedUrl.includes(tenantPlaceholder)) {
    throw new AppError(`Object pair template "${template.id}" uses {{TENANT_ID}}, which is not supported in this first version.`, "OBJECT_PAIR_TEMPLATE_UNSUPPORTED");
  }

  if (!template.url.startsWith("http://") && !template.url.startsWith("https://")) {
    throw new AppError(`Object pair template "${template.id}" must use http or https.`, "OBJECT_PAIR_TEMPLATE_PROTOCOL_INVALID");
  }

  if (forbiddenEndpointWords.test(template.url)) {
    throw new AppError(`Object pair template "${template.id}" appears to target a state-changing endpoint.`, "OBJECT_PAIR_TEMPLATE_UNSAFE_ENDPOINT");
  }

  if (urlHasEmbeddedSecret(template.url)) {
    throw new AppError(`Object pair template "${template.id}" appears to contain secret-like material.`, "OBJECT_PAIR_TEMPLATE_SECRET_FORBIDDEN");
  }

  for (const [name, value] of Object.entries(template.headers)) {
    if (name.toLowerCase() === "authorization" || name.toLowerCase() === "cookie" || name.toLowerCase().startsWith("x-csrf")) {
      throw new AppError(`Object pair template "${template.id}" must not embed authentication headers.`, "OBJECT_PAIR_TEMPLATE_AUTH_FORBIDDEN");
    }
    if (secretLikePattern.test(name) || secretLikePattern.test(value)) {
      throw new AppError(`Object pair template "${template.id}" appears to contain secret-like header material.`, "OBJECT_PAIR_TEMPLATE_SECRET_FORBIDDEN");
    }
  }

  try {
    normalizeUrl(applyObjectPlaceholder(template.url, "routecairn-object"));
  } catch {
    throw new AppError(`Object pair template "${template.id}" does not produce a valid URL.`, "OBJECT_PAIR_TEMPLATE_URL_INVALID");
  }
}

function applyObjectPlaceholder(templateUrl: string, objectId: string): string {
  return templateUrl.split(objectPlaceholder).join(encodeURIComponent(objectId)).split(encodedObjectPlaceholder).join(encodeURIComponent(objectId));
}

function decodeTemplatePlaceholders(templateUrl: string): string {
  return templateUrl.split(encodedObjectPlaceholder).join(objectPlaceholder).split(encodedTenantPlaceholder).join(tenantPlaceholder);
}

function validateIdentifier(value: string, label: string): void {
  if (value.length > maxIdentifierLength || generatorPattern.test(value) || numericRangePattern.test(value) || value.includes(",") || value.includes("\n") || value.includes("\r")) {
    throw new AppError(`Object pair identifier "${label}" must be one exact operator-supplied value, not a range, wildcard, list, or generator.`, "OBJECT_PAIR_IDENTIFIER_UNSAFE");
  }
}

function validateAssertionEvidence(assertion: ObjectPairInput["cases"][number]["accountAObject"], label: string): void {
  for (const field of [assertion.expectedObjectIdField, assertion.expectedOwnerField, assertion.expectedTenantField].filter(Boolean)) {
    if (!fieldPathPattern.test(field as string)) {
      throw new AppError(`Object pair evidence field "${label}" uses an unsupported selector.`, "OBJECT_PAIR_EVIDENCE_SELECTOR_INVALID");
    }
  }

  for (const header of [assertion.expectedObjectIdHeader, assertion.expectedOwnerHeader, ...(assertion.expectedPrivateHeaders ?? [])].filter(Boolean)) {
    if (!headerNamePattern.test(header as string)) {
      throw new AppError(`Object pair evidence header "${label}" uses an unsupported selector.`, "OBJECT_PAIR_EVIDENCE_SELECTOR_INVALID");
    }
  }
}

function urlHasEmbeddedSecret(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) {
      return true;
    }
    for (const [name, value] of parsed.searchParams) {
      if (secretLikePattern.test(name) || secretLikePattern.test(value)) {
        return true;
      }
    }
    return false;
  } catch {
    return secretLikePattern.test(url);
  }
}

function validateInputUniqueness(input: ObjectPairInput): void {
  const caseIds = new Set<string>();
  const logicalPairs = new Set<string>();

  for (const testCase of input.cases) {
    if (caseIds.has(testCase.id)) {
      throw new AppError(`Object pair case "${testCase.id}" is duplicated.`, "OBJECT_PAIR_DUPLICATE_CASE");
    }
    caseIds.add(testCase.id);

    const pairKey = [testCase.template.method, testCase.template.url, testCase.accountAObject.id, testCase.accountBObject.id].join("\0");
    if (logicalPairs.has(pairKey)) {
      throw new AppError(`Object pair case "${testCase.id}" duplicates an existing logical object pair.`, "OBJECT_PAIR_DUPLICATE_LOGICAL_PAIR");
    }
    logicalPairs.add(pairKey);
  }
}

function validateDistinctPrincipals(profileSet: AuthProfileSet): void {
  const accountA = stableAuthFingerprint(profileSet.accountA.headers, profileSet.accountA.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  const accountB = stableAuthFingerprint(profileSet.accountB.headers, profileSet.accountB.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  if (accountA === accountB) {
    throw new AppError("Object pair testing requires distinct Account A and Account B authentication contexts.", "OBJECT_PAIR_IDENTICAL_PRINCIPALS");
  }
}

function validateDeclaredPrincipalIdentity(profileSet: AuthProfileSet, principals: ObjectPairInput["principals"]): void {
  const principalA = profileSet.accountA.principalId;
  const principalB = profileSet.accountB.principalId;
  if (!principalA || !principalB) {
    throw new AppError("Object pair testing requires declared principalId metadata in both Account A and Account B auth profiles.", "OBJECT_PAIR_PRINCIPAL_ID_REQUIRED");
  }

  if (principalA === principalB) {
    throw new AppError("Object pair testing requires Account A and Account B to declare different principalId values.", "OBJECT_PAIR_IDENTICAL_PRINCIPAL_ID");
  }

  if (principals.accountA.expectedAccountId && principals.accountA.expectedAccountId !== principalA) {
    throw new AppError("Account A declared principalId does not match object-pair expectedAccountId metadata.", "OBJECT_PAIR_PRINCIPAL_ID_MISMATCH");
  }
  if (principals.accountB.expectedAccountId && principals.accountB.expectedAccountId !== principalB) {
    throw new AppError("Account B declared principalId does not match object-pair expectedAccountId metadata.", "OBJECT_PAIR_PRINCIPAL_ID_MISMATCH");
  }
}

function requirePrincipalId(value: string | undefined, label: string): string {
  if (!value) {
    throw new AppError(`Object pair testing requires declared principalId metadata for ${label}.`, "OBJECT_PAIR_PRINCIPAL_ID_REQUIRED");
  }
  return value;
}

function principalPlanningInput(principals: ObjectPairInput["principals"], profileSet: AuthProfileSet): ObjectPairInput["principals"] {
  return {
    accountA: {
      expectedAccountId: profileSet.accountA.principalId,
      ...(profileSet.accountA.tenantId ?? principals.accountA.tenantId ? { tenantId: profileSet.accountA.tenantId ?? principals.accountA.tenantId } : {}),
      ...(profileSet.accountA.role ?? principals.accountA.role ? { role: profileSet.accountA.role ?? principals.accountA.role } : {})
    },
    accountB: {
      expectedAccountId: profileSet.accountB.principalId,
      ...(profileSet.accountB.tenantId ?? principals.accountB.tenantId ? { tenantId: profileSet.accountB.tenantId ?? principals.accountB.tenantId } : {}),
      ...(profileSet.accountB.role ?? principals.accountB.role ? { role: profileSet.accountB.role ?? principals.accountB.role } : {})
    }
  };
}

function stableAuthFingerprint(headers: Record<string, string>, cookies: string): string {
  return createHash("sha256").update(JSON.stringify(Object.entries(headers).sort())).update(cookies).digest("hex");
}

function objectIdHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) {
    return value;
  }
  Object.freeze(value);
  for (const item of Object.values(value)) {
    deepFreeze(item);
  }
  return value;
}
