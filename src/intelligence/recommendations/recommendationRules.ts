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
  "Sensitive File Exposure": "Remove the file from the public web root, rotate exposed secrets, and verify deployment rules prevent recurrence.",
  "Backup File Exposure": "Remove public backup/archive files and store backups outside the web root with access controls.",
  "Config Exposure": "Remove public configuration files and verify they do not contain sensitive environment or service details.",
  "Debug/Dev Path": "Disable debug tooling in production or restrict it to authenticated administrative networks.",
  "Directory Listing": "Disable directory listing and ensure only intended files are publicly served.",
  "Source Map Exposure": "Review whether source maps should be public; remove or restrict them if they expose source code or sensitive comments.",
  "Public Cloud Reference": "Review referenced cloud resources for intended public exposure and least-privilege access controls.",
  "Interesting But Needs Manual Testing": "Review manually for intended public exposure and access-control behavior."
};
