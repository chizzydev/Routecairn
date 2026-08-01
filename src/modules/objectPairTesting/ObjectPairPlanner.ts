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
const forbiddenEndpointWords = /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read)/i;
const generatorPattern = /(?:\.\.|\*|\[|\]|\{|\}|\||regex|range|increment|decrement|random|uuid-v|prefix|suffix)/i;
const numericRangePattern = /^\s*\d+\s*-\s*\d+\s*$/;

const visibilitySchema = z.enum(["PRIVATE_TO_OWNER", "SHARED_WITH_SPECIFIC_PRINCIPALS", "TENANT_VISIBLE", "ROLE_VISIBLE", "PUBLIC", "UNKNOWN_REQUIRES_REVIEW"]);

const objectAssertionSchema = z.object({
  id: z.string().min(1),
  source: z.string().min(1),
  confirmedSafeToTest: z.literal(true),
  readOnly: z.literal(true),
  tenantId: z.string().min(1).optional(),
  expectedObjectIdField: z.string().min(1).optional(),
  expectedOwnerField: z.string().min(1).optional(),
  expectedTenantField: z.string().min(1).optional(),
  expectedSafeMarkers: z.array(z.string().min(1)).default([]),
  expectedPrivateFields: z.array(z.string().min(1)).default([])
});

const caseSchema = z.object({
  id: z.string().min(1),
  objectType: z.string().min(1),
  expectedVisibility: visibilitySchema.default("PRIVATE_TO_OWNER"),
  template: z.object({
    id: z.string().min(1),
    method: z.enum(["GET", "HEAD"]),
    url: z.string().min(1),
    headers: z.record(z.string()).default({})
  }),
  accountAObject: objectAssertionSchema,
  accountBObject: objectAssertionSchema
});

const objectPairInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxPairs: z.number().int().positive().max(20).default(maxDefaultPairs),
  principals: z
    .object({
      accountA: z
        .object({
          expectedAccountId: z.string().min(1).optional(),
          tenantId: z.string().min(1).optional(),
          role: z.string().min(1).optional()
        })
        .default({}),
      accountB: z
        .object({
          expectedAccountId: z.string().min(1).optional(),
          tenantId: z.string().min(1).optional(),
          role: z.string().min(1).optional()
        })
        .default({})
    })
    .default({ accountA: {}, accountB: {} }),
  cases: z.array(caseSchema).min(1).max(20)
});

export type ObjectPairInput = z.infer<typeof objectPairInputSchema>;

export async function loadObjectPairInput(filePath: string): Promise<ObjectPairInput> {
  const raw = (await readFile(filePath, "utf8")).replace(/^\uFEFF/, "");
  const parsed = objectPairInputSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "OBJECT_PAIR_INPUT_INVALID");
  }
  return parsed.data;
}

export function planObjectPairTesting(input: ObjectPairInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): ObjectPairTestingPlan {
  if (!options.authProfileSet) {
    throw new AppError("Object pair testing requires --auth-a and --auth-b.", "OBJECT_PAIR_AUTH_PAIR_REQUIRED");
  }

  validateDistinctPrincipals(options.authProfileSet);
  if (input.cases.length > input.maxPairs) {
    throw new AppError(`Object pair input contains ${input.cases.length} cases, exceeding maxPairs ${input.maxPairs}.`, "OBJECT_PAIR_TOO_MANY_CASES");
  }

  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const principals: ObjectPairPrincipalPlan[] = [
    {
      label: "account_a",
      redactedLabel: options.authProfileSet.accountA.label,
      ...(input.principals.accountA.expectedAccountId ? { expectedAccountId: input.principals.accountA.expectedAccountId } : {}),
      ...(input.principals.accountA.tenantId ? { tenantId: input.principals.accountA.tenantId } : {}),
      ...(input.principals.accountA.role ? { role: input.principals.accountA.role } : {})
    },
    {
      label: "account_b",
      redactedLabel: options.authProfileSet.accountB.label,
      ...(input.principals.accountB.expectedAccountId ? { expectedAccountId: input.principals.accountB.expectedAccountId } : {}),
      ...(input.principals.accountB.tenantId ? { tenantId: input.principals.accountB.tenantId } : {}),
      ...(input.principals.accountB.role ? { role: input.principals.accountB.role } : {})
    }
  ];

  const cases = input.cases.map((testCase) => planCase(testCase, scopeMatcher));
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

function planCase(testCase: ObjectPairInput["cases"][number], scopeMatcher: ScopeMatcher): ObjectPairCasePlan {
  validateIdentifier(testCase.accountAObject.id, `${testCase.id}.accountAObject.id`);
  validateIdentifier(testCase.accountBObject.id, `${testCase.id}.accountBObject.id`);
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

  const accountAObject = ownershipAssertion(testCase.accountAObject, testCase.objectType, "account_a", testCase.expectedVisibility);
  const accountBObject = ownershipAssertion(testCase.accountBObject, testCase.objectType, "account_b", testCase.expectedVisibility);

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
  expectedVisibility: ObjectVisibilityExpectation
): ObjectOwnershipAssertionPlan {
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
    ...(assertion.expectedTenantField ? { expectedTenantField: assertion.expectedTenantField } : {}),
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

  for (const name of Object.keys(template.headers)) {
    if (name.toLowerCase() === "authorization" || name.toLowerCase() === "cookie" || name.toLowerCase().startsWith("x-csrf")) {
      throw new AppError(`Object pair template "${template.id}" must not embed authentication headers.`, "OBJECT_PAIR_TEMPLATE_AUTH_FORBIDDEN");
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
  if (generatorPattern.test(value) || numericRangePattern.test(value) || value.includes(",") || value.includes("\n") || value.includes("\r")) {
    throw new AppError(`Object pair identifier "${label}" must be one exact operator-supplied value, not a range, wildcard, list, or generator.`, "OBJECT_PAIR_IDENTIFIER_UNSAFE");
  }
}

function validateDistinctPrincipals(profileSet: AuthProfileSet): void {
  const accountA = stableAuthFingerprint(profileSet.accountA.headers, profileSet.accountA.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  const accountB = stableAuthFingerprint(profileSet.accountB.headers, profileSet.accountB.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  if (accountA === accountB) {
    throw new AppError("Object pair testing requires distinct Account A and Account B authentication contexts.", "OBJECT_PAIR_IDENTICAL_PRINCIPALS");
  }
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
