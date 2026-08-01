import type {
  AuthSurfaceReport,
  ParameterAnalysisReport,
  RoleComparisonReport,
  StateAwareApiReport,
  VulnerabilityWorkflow,
  WorkflowEvidenceTemplate
} from "../../reports/ReportTypes.js";

export interface EvidenceTemplateInput {
  workflows: VulnerabilityWorkflow[];
  authSurface?: AuthSurfaceReport | undefined;
  roleComparison?: RoleComparisonReport | undefined;
  stateAwareApi?: StateAwareApiReport | undefined;
  parameterAnalysis?: ParameterAnalysisReport | undefined;
}

export function buildEvidenceTemplates(input: EvidenceTemplateInput): WorkflowEvidenceTemplate[] {
  const templates = new Map<string, WorkflowEvidenceTemplate>();

  for (const workflow of input.workflows) {
    if (workflow.category === "idor-bola") addTemplate(templates, idorBolaTemplate(workflow.target, workflow.relatedEndpoints));
    if (workflow.category === "auth-session") addTemplate(templates, authBypassTemplate(workflow.target, workflow.relatedEndpoints));
    if (workflow.category === "rate-limit") addTemplate(templates, rateLimitTemplate(workflow.target, workflow.relatedEndpoints));
    if (workflow.category === "graphql") addTemplate(templates, graphQlTemplate(workflow.target, workflow.relatedEndpoints));
  }

  for (const review of input.stateAwareApi?.bolaIdorCandidates ?? []) addTemplate(templates, idorBolaTemplate(review.endpoint, [review.endpoint]));
  for (const review of input.stateAwareApi?.reviewedEndpoints ?? []) if (review.candidateReasons.includes("export-download")) addTemplate(templates, exportDownloadTemplate(review.endpoint, [review.endpoint]));
  for (const target of input.parameterAnalysis?.workflowTargets ?? []) {
    if (target.reasons.includes("business-logic")) addTemplate(templates, priceFilterTemplate(target.url, [target.url]));
    if (target.reasons.includes("authorization-sensitive") || target.reasons.includes("object-id")) addTemplate(templates, idorBolaTemplate(target.url, [target.url]));
  }
  for (const result of input.roleComparison?.results ?? []) if (["account-a-only", "account-b-only", "only-authenticated-access"].includes(result.classification)) addTemplate(templates, idorBolaTemplate(result.url, [result.url]));
  for (const surface of input.authSurface?.surfaces ?? []) if (["login", "password reset", "session", "oauth", "otp", "magic link"].includes(surface.purpose)) addTemplate(templates, authBypassTemplate(surface.endpoint, [surface.endpoint]));

  return [...templates.values()].sort((left, right) => priorityRank(right.priority) - priorityRank(left.priority) || left.title.localeCompare(right.title));
}

function base(input: Omit<WorkflowEvidenceTemplate, "needsManualVerification">): WorkflowEvidenceTemplate {
  return { ...input, relatedEndpoints: unique([input.target, ...input.relatedEndpoints]).slice(0, 20), needsManualVerification: true };
}

function idorBolaTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "idor-bola", title: "IDOR/BOLA Proof Collection Template", priority: "high", target, relatedEndpoints,
    preconditions: ["Use two accounts you own or are explicitly authorized to test.", "Identify objects owned separately by Account A and Account B.", "Start with safe retrieval requests only."],
    steps: ["Capture Account A's normal request and response summary.", "Repeat as Account B with only the object identifier changed or preserved as needed.", "Compare status, redirect, cache headers, content length, body hash, and whether cross-account data appears.", "Repeat anonymously to confirm whether authentication is required."],
    expectedSecureBehavior: ["Account B cannot access Account A owned data unless business rules allow it.", "Unauthorized access returns 401, 403, safe redirect, or generic no-access response.", "Private data responses are not cacheable across users."],
    evidenceToCapture: ["Redacted Account A request/response summary.", "Redacted Account B replay request/response summary.", "Status codes, final URLs, content lengths, hashes, and cache headers.", "Minimal sanitized excerpt only if needed and allowed."],
    avoidActions: ["Do not enumerate IDs or test objects you do not own.", "Do not modify, delete, purchase, invite, message, or submit state-changing actions.", "Do not store full private payloads."] });
}

function authBypassTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "auth-bypass", title: "Auth Bypass And Session Boundary Template", priority: "high", target, relatedEndpoints,
    preconditions: ["Use accounts you control and a clean anonymous session.", "Know the intended access state for the route.", "Avoid brute force, OTP guessing, or MFA bypass unless explicitly authorized."],
    steps: ["Request the route anonymously and record status, redirect, cache headers, and response shape.", "Request authenticated and compare response summaries.", "Log out or remove auth cookies and request again.", "Compare Account A and Account B behavior where roles exist."],
    expectedSecureBehavior: ["Private routes require valid authentication.", "Logged-out or expired sessions cannot access authenticated resources.", "Anonymous users do not receive private account, token, or role state."],
    evidenceToCapture: ["Anonymous/authenticated status and redirect differences.", "Set-Cookie and cache-control headers relevant to session state.", "Redacted curl commands or browser request summaries."],
    avoidActions: ["Do not brute force credentials, reset links, OTPs, or magic links.", "Do not test accounts you do not control.", "Do not bypass MFA or social login outside permission."] });
}

function rateLimitTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "rate-limit", title: "Rate Limit Proof Collection Template", priority: "medium", target, relatedEndpoints,
    preconditions: ["Confirm program rules allow low-volume abuse-control testing.", "Use identifiers you control.", "Define a tiny request count such as 3 to 5 requests."],
    steps: ["Send a small controlled set and stop if throttling appears.", "Record status codes, Retry-After headers, response times, and messages.", "Check account/IP/identifier/session scope where allowed."],
    expectedSecureBehavior: ["Sensitive endpoints enforce throttling or abuse controls.", "Responses avoid account enumeration.", "Cooldown behavior appears when throttled."],
    evidenceToCapture: ["Timestamped request count and status sequence.", "Rate-limit headers and Retry-After values.", "Proof that testing stayed low-volume."],
    avoidActions: ["Do not run high-volume traffic.", "Do not send reset/OTP/invite messages to third parties.", "Do not continue after lockout, captcha, or throttling."] });
}

function graphQlTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "graphql", title: "GraphQL Safe Evidence Template", priority: "medium", target, relatedEndpoints,
    preconditions: ["Confirm the endpoint is GraphQL-like.", "Use only safe queries unless mutations are explicitly allowed.", "Use only accounts you control."],
    steps: ["Check OPTIONS/HEAD/GET behavior first.", "Send a benign __typename query if allowed.", "Capture minimal introspection evidence only if relevant.", "Review auth, errors, batching, and complexity conservatively."],
    expectedSecureBehavior: ["Mutations require authentication and authorization.", "Sensitive schema or resolver errors are not exposed unintentionally.", "Depth, batching, and complexity controls limit expensive queries."],
    evidenceToCapture: ["Endpoint behavior summary and allowed methods.", "Minimal benign query response summary.", "Authentication requirement differences and redacted errors."],
    avoidActions: ["Do not execute mutations without permission.", "Do not run expensive nested queries or batching stress tests.", "Do not store full schemas unnecessarily."] });
}

function exportDownloadTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "export-download", title: "Export/Download Access Evidence Template", priority: "high", target, relatedEndpoints,
    preconditions: ["Use files or exports generated by accounts you control.", "Prefer retrieval-only checks.", "Prepare distinct test data for Account A and Account B."],
    steps: ["Request Account A's export as Account A.", "Request the same URL as Account B and anonymously.", "Compare filename, type, length, status, cache headers, and cross-account data.", "Check signed URL expiry and account/session binding."],
    expectedSecureBehavior: ["Only owner or authorized role can retrieve private exports.", "Signed URLs expire and do not expose other users' data.", "Private downloads are not publicly cacheable."],
    evidenceToCapture: ["Redacted summaries for Account A, Account B, and anonymous contexts.", "Content type, content length, cache-control, content-disposition, and status.", "Minimal sanitized excerpt only if unauthorized exposure is confirmed."],
    avoidActions: ["Do not retain large private files.", "Do not access exports belonging to real users outside authorization.", "Do not trigger mass exports or resource-heavy jobs."] });
}

function priceFilterTemplate(target: string, relatedEndpoints: string[]): WorkflowEvidenceTemplate {
  return base({ kind: "price-filter", title: "Price/Filter Business Logic Template", priority: "medium", target, relatedEndpoints,
    preconditions: ["Use your own product, cart, search, or test account data.", "Stay on read-only views unless mutation testing is authorized.", "Know expected server-side rules for price/filter behavior."],
    steps: ["Change one price/filter/sort/search parameter at a time.", "Check whether client-controlled values affect server-side price, discount, eligibility, or inventory.", "Compare displayed values with server-confirmed values.", "Stop before checkout/payment/order submission unless authorized."],
    expectedSecureBehavior: ["Server-side pricing and eligibility are authoritative.", "Filters and sorting do not expose unauthorized data or alter final prices.", "Unexpected values are validated, rejected, or normalized."],
    evidenceToCapture: ["Original and modified parameter values.", "Status, visible changes, and server-side confirmation where available.", "Screenshots or redacted excerpts without completing transactions."],
    avoidActions: ["Do not place real orders or trigger payments.", "Do not reserve inventory or abuse coupons/balances.", "Do not test against third-party user data."] });
}

function addTemplate(templates: Map<string, WorkflowEvidenceTemplate>, value: WorkflowEvidenceTemplate): void {
  const key = `${value.kind}:${value.target}`;
  if (!templates.has(key)) templates.set(key, value);
}
function unique(values: string[]): string[] { return [...new Set(values.filter(Boolean))].sort(); }
function priorityRank(priority: WorkflowEvidenceTemplate["priority"]): number { return { low: 0, medium: 1, high: 2 }[priority]; }
