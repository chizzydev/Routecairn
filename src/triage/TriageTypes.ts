import { z } from "zod";

export const triageStatusSchema = z.enum(["reviewed", "false-positive", "confirmed", "needs-retest"]);
export type TriageStatus = z.infer<typeof triageStatusSchema>;

export const triageEntrySchema = z.object({
  findingId: z.string().min(1),
  status: triageStatusSchema,
  note: z.string().default(""),
  updatedAt: z.string().datetime(),
  updatedBy: z.string().min(1).default("routecairn")
});

export const triageStateSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  reportTarget: z.string().optional(),
  reportGeneratedAt: z.string().optional(),
  entries: z.record(z.string(), triageEntrySchema).default({})
});

export type TriageEntry = z.infer<typeof triageEntrySchema>;
export type TriageState = z.infer<typeof triageStateSchema>;

export function emptyTriageState(reportTarget?: string, reportGeneratedAt?: string): TriageState {
  return {
    schemaVersion: 1,
    ...(reportTarget ? { reportTarget } : {}),
    ...(reportGeneratedAt ? { reportGeneratedAt } : {}),
    entries: {}
  };
}