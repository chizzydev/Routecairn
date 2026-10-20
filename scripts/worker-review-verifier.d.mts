export interface ReviewWorktree {
  status: { status: string; path: string }[];
  members: string[];
  refs: string[];
  index: string[];
}
export function parseStatus(bytes: Buffer): ReviewWorktree["status"];
export function assertWorktreeMembership(expected: ReviewWorktree, actual: ReviewWorktree): void;
export function snapshotWorktree(repository: string): ReviewWorktree;
export function verifyWorkerReview(packet: string, repository: string): {
  readOnly: true;
  exactPendingPaths: number;
  exactNonignoredFiles: number;
  verifiedWorkingTreeFiles: number;
  verifiedPacketMembers: number;
  protectedGeneratedFiles: number;
  patchesReverseCheck: "PASS";
  operationalExecution: "HOLD";
  fullAcceptanceClaimed: false;
};
