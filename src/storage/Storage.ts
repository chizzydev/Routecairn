export interface StoredScanSummary {
  id: string;
  target: string;
  startedAt: string;
  completedAt?: string;
  reportPath: string;
}

export interface Storage<TScan = unknown> {
  saveScan(scanId: string, scan: TScan): Promise<string>;
  loadScan(scanId: string): Promise<TScan>;
  listScans(): Promise<StoredScanSummary[]>;
}
