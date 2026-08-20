import type { FindingType } from "../../core/findings/Finding.js";

export const recommendationRules: Record<FindingType, string> = {
  "Admin/Login Panel": "Review whether this route is intended to be public and test access-control behavior within the authorized scope.",
  "API Endpoint": "Verify intended exposure and manually test authorization, object access, data exposure, and rate limiting.",
  "GraphQL Endpoint": "Verify intended exposure and manually test introspection, batching, depth limits, and authorization behavior.",
  "Security Header Issue": "Tune security headers according to application behavior and deployment requirements.",
  "Cookie Issue": "Set appropriate Secure, HttpOnly, SameSite, and Domain attributes based on cookie purpose.",
  "CORS Issue": "Restrict allowed origins to trusted origins and avoid credentials with wildcard or reflected origins.",
  "HTTP Method Issue": "Verify unsafe methods are required and protected by authentication and authorization controls.",
  "Object Authorization Issue": "Enforce server-side object authorization by checking owner, tenant, sharing, or role permission before returning private object fields.",
  "Field Exposure Issue": "Apply field-level authorization and response shaping before serializing sensitive fields for non-owner, public, tenant, or lower-privileged actors.",
  "Authorization Matrix Issue": "Enforce server-side authorization decisions consistently across declared roles, tenants, account states, relationships, and object states before returning protected objects.",
  "Equivalent Route Authorization Issue": "Apply the same centralized authorization policy across canonical, legacy, versioned, nested, export, mobile, alias, and compatibility routes that expose the same protected object.",
  "Collection Authorization Issue": "Filter collection, listing, search, count, and summary responses server-side using trusted principal, tenant, role, account-state, object-owner, and object-state authorization before returning results.",
  "Bulk Authorization Issue": "Authorize every object in non-mutating bulk preview, validation, dry-run, and summary workflows using trusted principal, tenant, role, account-state, owner, and object-state policy before returning bulk results.",
  "File Authorization Issue": "Authorize every file metadata, preview, download, and signed-URL issuance request using trusted principal, tenant, role, account-state, owner, sharing, and file-state policy before returning file data.",
  "Sensitive File Exposure": "Remove the file from the public web root, rotate exposed secrets, and verify deployment rules prevent recurrence.",
  "Backup File Exposure": "Remove public backup/archive files and store backups outside the web root with access controls.",
  "Config Exposure": "Remove public configuration files and verify they do not contain sensitive environment or service details.",
  "Debug/Dev Path": "Disable debug tooling in production or restrict it to authenticated administrative networks.",
  "Directory Listing": "Disable directory listing and ensure only intended files are publicly served.",
  "Source Map Exposure": "Review whether source maps should be public; remove or restrict them if they expose source code or sensitive comments.",
  "Public Cloud Reference": "Review referenced cloud resources for intended public exposure and least-privilege access controls.",
  "Interesting But Needs Manual Testing": "Review manually for intended public exposure and access-control behavior."
};
