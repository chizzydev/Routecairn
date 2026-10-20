# Engineering continuity v0.20 — Decide offline preparation

Builds on source-first main c1532aa672c0efb9e4cebf1c281a1ffb7949f1e1 and frozen Stage C 8192cda2b8475306ecbec215f7c3623d74af25ee. See DECIDE_PILOT_PREPARATION_v0.20.md for source-backed inventory and conditional owner proposal.

Completed: read-only reconnaissance of real decide-api/decide-web/dm; actual authentication and per-user/admin boundaries; offline onboarding compatibility explanations in the existing dashboard, with focused regression tests. Source declares no tenant identity, normal authenticated GETs update session metadata, saved/me returns a collection, and current backend startup starts jobs. No Decide services, imports, requests, configuration edits, sessions or database operations were performed. No finding or full application assessment is claimed.

Decide native pilot remains BLOCKED: three genuine approved profiles absent; tenantless actor proof unsupported; collection ownership not expressible by scalar observation paths; isolated schema/users provisioning and runtime/job isolation unestablished; authenticated GET housekeeping needs separate owner review. Preserve all server and native proof guards.

Preserved historical results: 382 distinct selected assertions and 35 Edge scenarios passed previously; 10 unresolved original 30-second combined-run timeouts. New focused results are recorded separately in the lean packet; they do not replace unresolved failures or establish independent accuracy. No full-suite rerun solely for packaging.

Next product priority: tenantless principal/role and bounded collection ownership evidence, extending existing guided mapping and actor attribution rather than a parallel scanner. Separate owner-approved local Decide bootstrap and minimal exact GET/session-effect scope must precede real runtime work.

Roadmap RC000–019/M0–M6 and prior complete work remain. Ubuntu paused. Trusted Discovery execution, Stage D, target state-changing execution, external/unrestricted scanning and release remain HOLD. Preserve all prior evidence and operational data; no cleanup was performed. Source-first public backup after review, exact Git provenance and ONE lean under-20MiB review ZIP remain mandatory. Do not recursively inherit old snapshots. Retained detailed history is referenced by hash, not duplicated. Final commit and exact remote identity are in the packet provenance to avoid a self-referential commit value here.
