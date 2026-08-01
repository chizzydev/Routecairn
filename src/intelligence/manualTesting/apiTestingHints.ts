export const apiTestingHints = {
  bola: "Test object-level authorization by changing IDs and confirming access is denied across users or roles.",
  functionAuthorization: "Test broken function-level authorization by attempting the same endpoint with lower-privileged roles.",
  excessiveData: "Review the response for excessive data exposure, hidden fields, internal identifiers, or role metadata.",
  massAssignment: "If write methods exist later, test whether unexpected properties can be assigned.",
  rateLimit: "Test rate limiting and abuse controls with safe, authorized request volumes.",
  exportAbuse: "Review export/download behavior for authorization, filtering, and excessive data exposure.",
  graphql: "Test GraphQL introspection, depth limits, batching, authorization, and excessive data exposure."
} as const;
